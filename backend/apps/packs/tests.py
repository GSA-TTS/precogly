"""Tests for path-based pack discovery, O(1) lookup (issue #33),
taxonomy reference validation (issue #26), and pack validation gaps (issue #10)."""

import importlib.util
import tempfile
from pathlib import Path
from unittest import mock

import yaml
from django.test import SimpleTestCase, TestCase, override_settings

from apps.packs.services import (
    ImportResult,
    _find_pack_dir,
    _is_valid_slug,
    discover_packs_from_source,
    get_libraries_path,
    import_pack_from_path,
    validate_pack,
)


def _empty_pack_queryset():
    """Stand-in for LibraryPack.objects.all() that yields nothing.

    discover_packs_from_source() reads installed packs from the DB to
    flag is_in_database; tests covering on-disk discovery don't care
    about that signal, so we mock the queryset instead of spinning up a
    real database.
    """
    return iter([])


def _write_pack(base_dir: Path, relative_path: str, slug: str, **overrides) -> Path:
    """Create a minimal pack on disk under base_dir/relative_path."""
    pack_dir = base_dir / relative_path
    pack_dir.mkdir(parents=True, exist_ok=True)

    pack_meta = {
        "slug": slug,
        "name": slug,
        "version": "1.0.0",
        "pack_type": "technology",
        "author": "Test",
    }
    pack_meta.update(overrides)

    pack_yaml = pack_dir / "pack.yaml"
    pack_yaml.write_text(yaml.safe_dump({"pack": pack_meta}))
    return pack_dir


def _load_nist_generator():
    path = Path(__file__).resolve().parents[3] / "scripts/generate_nist_800_53_pack.py"
    spec = importlib.util.spec_from_file_location("generate_nist_800_53_pack", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NistPackGeneratorTests(SimpleTestCase):
    def test_canonical_control_id_preserves_enhancement_identity(self):
        generator = _load_nist_generator()
        self.assertEqual(generator.canonical_control_id("ac-02"), "AC-2")
        self.assertEqual(generator.canonical_control_id("ac-2.01"), "AC-2(1)")

    def test_build_pack_preserves_names_prose_parameters_and_hierarchy(self):
        generator = _load_nist_generator()
        document = {
            "catalog": {
                "uuid": "catalog-uuid",
                "metadata": {
                    "title": "NIST catalog",
                    "version": "5.2.0",
                    "oscal-version": "1.2.2",
                },
                "groups": [
                    {
                        "id": "ac",
                        "controls": [
                            {
                                "id": "ac-2",
                                "title": "Account Management",
                                "params": [{"id": "ac-2_prm_1"}],
                                "parts": [
                                    {
                                        "name": "statement",
                                        "parts": [
                                            {
                                                "name": "item",
                                                "prose": "Manage accounts.",
                                            }
                                        ],
                                    },
                                    {
                                        "name": "guidance",
                                        "prose": "Not requirement prose.",
                                    },
                                ],
                                "controls": [
                                    {
                                        "id": "ac-2.1",
                                        "title": "Automated System Account Management",
                                        "parts": [
                                            {
                                                "name": "statement",
                                                "prose": "Automate accounts.",
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        }

        requirements = generator.build_pack(document, "digest")["frameworks"][0][
            "requirements"
        ]

        self.assertEqual(requirements[0]["section_code"], "AC-2")
        self.assertEqual(requirements[0]["name"], "Account Management")
        self.assertEqual(requirements[0]["description"], "Manage accounts.")
        self.assertEqual(
            requirements[0]["format_metadata"]["parameters"], ["ac-2_prm_1"]
        )
        self.assertEqual(requirements[1]["section_code"], "AC-2(1)")
        self.assertEqual(requirements[1]["parent"], "AC-2")
        self.assertEqual(requirements[1]["requirement_type"], "enhancement")

    def test_generated_pack_contains_complete_canonical_catalog(self):
        pack_path = (
            Path(__file__).resolve().parents[3]
            / "libraries/packs/standards/nist-800-53-r5/pack.yaml"
        )
        pack = yaml.safe_load(pack_path.read_text())
        requirements = pack["frameworks"][0]["requirements"]
        section_codes = [requirement["section_code"] for requirement in requirements]

        self.assertEqual(len(requirements), 1196)
        self.assertEqual(len(set(section_codes)), 1196)
        self.assertEqual(
            sum(
                requirement["requirement_type"] == "control"
                for requirement in requirements
            ),
            324,
        )
        self.assertEqual(
            sum(
                requirement["requirement_type"] == "enhancement"
                for requirement in requirements
            ),
            872,
        )
        self.assertFalse(
            [
                requirement["section_code"]
                for requirement in requirements
                if not requirement["description"]
                and requirement.get("status") != "withdrawn"
            ]
        )
        self.assertEqual(
            pack["pack"]["provenance"]["source_sha256"],
            "01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062",
        )


class FindPackDirTests(SimpleTestCase):
    """_find_pack_dir is O(1): it only checks the path it was given."""

    def test_resolves_top_level_pack(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_pack(base, "aws", slug="aws")

            result = _find_pack_dir(base, "aws")

            self.assertEqual(result, base / "aws")

    def test_resolves_nested_pack(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_pack(base, "frameworks/nist-csf", slug="nist-csf")

            result = _find_pack_dir(base, "frameworks/nist-csf")

            self.assertEqual(result, base / "frameworks" / "nist-csf")

    def test_returns_none_for_missing_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)

            self.assertIsNone(_find_pack_dir(base, "does-not-exist"))

    def test_returns_none_when_pack_yaml_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "empty-dir").mkdir()

            self.assertIsNone(_find_pack_dir(base, "empty-dir"))

    def test_does_not_recursively_scan(self):
        # If two packs share a slug under different paths, _find_pack_dir
        # must return the directory at the requested path, not any
        # other matching slug elsewhere in the tree.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_pack(base, "frameworks/nist-csf", slug="nist-csf")
            _write_pack(base, "demo/nist-csf", slug="nist-csf")

            framework_dir = _find_pack_dir(base, "frameworks/nist-csf")
            demo_dir = _find_pack_dir(base, "demo/nist-csf")

            self.assertEqual(framework_dir, base / "frameworks" / "nist-csf")
            self.assertEqual(demo_dir, base / "demo" / "nist-csf")
            self.assertNotEqual(framework_dir, demo_dir)


class DiscoveryAndDisambiguationTests(SimpleTestCase):
    """discover_packs_from_source computes relative_path from the filesystem."""

    def _patch_db_and_path(self, base):
        return mock.patch.multiple(
            "apps.packs.services",
            get_libraries_path=mock.MagicMock(return_value=base),
            LibraryPack=mock.MagicMock(
                objects=mock.MagicMock(
                    all=mock.MagicMock(return_value=_empty_pack_queryset()),
                )
            ),
        )

    def test_duplicate_slugs_under_different_paths_are_both_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self._patch_db_and_path(base):
                _write_pack(base, "frameworks/nist-csf", slug="nist-csf")
                _write_pack(base, "demo/nist-csf", slug="nist-csf")

                packs = discover_packs_from_source()
                nist_packs = [p for p in packs if p.slug == "nist-csf"]

                self.assertEqual(len(nist_packs), 2)
                paths = {p.relative_path for p in nist_packs}
                self.assertEqual(
                    paths,
                    {"frameworks/nist-csf", "demo/nist-csf"},
                )

    def test_relative_path_computed_from_filesystem(self):
        # relative_path should match the actual directory location,
        # regardless of what's in pack.yaml.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self._patch_db_and_path(base):
                _write_pack(base, "frameworks/owasp", slug="owasp")

                packs = discover_packs_from_source()
                owasp = next(p for p in packs if p.slug == "owasp")

                self.assertEqual(owasp.relative_path, "frameworks/owasp")

    def test_depends_on_with_path_disambiguates(self):
        # A pack depends on nist-csf and disambiguates which one via path.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self._patch_db_and_path(base):
                _write_pack(base, "frameworks/nist-csf", slug="nist-csf")
                _write_pack(base, "demo/nist-csf", slug="nist-csf")
                _write_pack(
                    base,
                    "consumer",
                    slug="consumer",
                    depends_on=[
                        {
                            "pack": "nist-csf",
                            "path": "demo/nist-csf",
                        }
                    ],
                )

                packs = discover_packs_from_source()
                consumer = next(p for p in packs if p.slug == "consumer")

                self.assertEqual(len(consumer.depends_on), 1)
                dep = consumer.depends_on[0]
                self.assertEqual(dep["slug"], "nist-csf")
                self.assertEqual(dep["path"], "demo/nist-csf")

    def test_path_format_string_depends_on_resolves(self):
        # depends_on with path-format strings like "taxonomies/stride-taxonomy"
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self._patch_db_and_path(base):
                _write_pack(base, "taxonomies/stride-taxonomy", slug="stride-taxonomy")
                _write_pack(
                    base,
                    "consumer",
                    slug="consumer",
                    depends_on=["taxonomies/stride-taxonomy"],
                )

                packs = discover_packs_from_source()
                consumer = next(p for p in packs if p.slug == "consumer")

                self.assertEqual(len(consumer.depends_on), 1)
                dep = consumer.depends_on[0]
                self.assertEqual(dep["slug"], "stride-taxonomy")
                self.assertEqual(dep["path"], "taxonomies/stride-taxonomy")


class TaxonomyReferenceValidationTests(SimpleTestCase):
    """validate_pack catches bad taxonomy slugs in joins/threats-*.yaml (#26)."""

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    def test_validate_rejects_unknown_taxonomy_reference(self, mock_taxonomy_model):
        mock_taxonomy_model.objects.values_list.return_value = []

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "bad-pack", slug="bad-pack")

            joins_dir = pack_dir / "joins"
            joins_dir.mkdir()
            join_data = {"taxonomy": "nonexistent-taxonomy", "mappings": []}
            (joins_dir / "threats-foo.yaml").write_text(yaml.safe_dump(join_data))

            result = validate_pack(pack_dir)

            taxonomy_errors = [e for e in result.errors if e.ref_type == "taxonomy"]
            self.assertEqual(len(taxonomy_errors), 1)
            self.assertEqual(taxonomy_errors[0].reference, "nonexistent-taxonomy")
            self.assertIn("taxonomy.yaml", taxonomy_errors[0].message)
            self.assertIn("not from the pack slug", taxonomy_errors[0].message)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    def test_validate_accepts_valid_taxonomy_reference(self, mock_taxonomy_model):
        mock_taxonomy_model.objects.values_list.return_value = []

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "good-pack", slug="good-pack")

            # Pack defines its own taxonomy
            tax_data = {"taxonomies": [{"slug": "cwe", "name": "CWE", "entries": []}]}
            (pack_dir / "taxonomy.yaml").write_text(yaml.safe_dump(tax_data))

            joins_dir = pack_dir / "joins"
            joins_dir.mkdir()
            join_data = {"taxonomy": "cwe", "mappings": []}
            (joins_dir / "threats-cwe.yaml").write_text(yaml.safe_dump(join_data))

            result = validate_pack(pack_dir)

            taxonomy_errors = [e for e in result.errors if e.ref_type == "taxonomy"]
            self.assertEqual(len(taxonomy_errors), 0)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.packs.services.get_libraries_path")
    def test_validate_accepts_taxonomy_from_dependency(
        self, mock_get_libraries_path, mock_lp, mock_taxonomy_model
    ):
        mock_taxonomy_model.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mock_get_libraries_path.return_value = base

            # Dependency pack provides the taxonomy
            dep_dir = _write_pack(
                base, "cwe-taxonomy", slug="cwe-taxonomy", pack_type="taxonomy"
            )
            tax_data = {"taxonomies": [{"slug": "cwe", "name": "CWE", "entries": []}]}
            (dep_dir / "taxonomy.yaml").write_text(yaml.safe_dump(tax_data))

            # Downstream pack references the dependency's taxonomy
            pack_dir = _write_pack(
                base,
                "cwe",
                slug="cwe",
                pack_type="threat",
                depends_on=["cwe-taxonomy"],
            )
            joins_dir = pack_dir / "joins"
            joins_dir.mkdir()
            join_data = {"taxonomy": "cwe", "mappings": []}
            (joins_dir / "threats-cwe.yaml").write_text(yaml.safe_dump(join_data))

            result = validate_pack(pack_dir)

            taxonomy_errors = [e for e in result.errors if e.ref_type == "taxonomy"]
            self.assertEqual(len(taxonomy_errors), 0)


# =========================================================================
# Phase 2: Duplicate ID detection (issue #10)
# =========================================================================


class FrameworkImportTests(TestCase):
    def test_framework_import_preserves_requirement_metadata_and_hierarchy(self):
        from apps.compliance.models import StandardFramework, StandardRequirement

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = Path(tmp) / "nist-pack"
            pack_dir.mkdir()
            pack_yaml = {
                "pack": {
                    "schema_version": 1,
                    "slug": "nist-pack",
                    "name": "NIST Pack",
                    "version": "1.0.0",
                    "pack_type": "compliance",
                },
                "frameworks": [
                    {
                        "slug": "nist-test",
                        "name": "NIST Test",
                        "requirements": [
                            {
                                "section_code": "AC-2(1)",
                                "name": "Enhancement",
                                "description": "Enhancement prose",
                                "parent": "AC-2",
                                "requirement_type": "enhancement",
                                "format_metadata": {"oscal_id": "ac-2.1"},
                            },
                            {
                                "section_code": "AC-2",
                                "name": "Account Management",
                                "description": "Control prose",
                                "requirement_type": "control",
                            },
                        ],
                    }
                ],
            }
            (pack_dir / "pack.yaml").write_text(yaml.safe_dump(pack_yaml))

            result = import_pack_from_path(pack_dir, force=True)

        self.assertTrue(result.success, result.errors)
        framework = StandardFramework.objects.get(slug="nist-test")
        parent = StandardRequirement.objects.get(
            framework=framework, section_code="AC-2"
        )
        enhancement = StandardRequirement.objects.get(
            framework=framework, section_code="AC-2(1)"
        )
        self.assertEqual(parent.name, "Account Management")
        self.assertEqual(parent.requirement_type, "control")
        self.assertEqual(enhancement.parent, parent)
        self.assertEqual(enhancement.format_metadata["oscal_id"], "ac-2.1")


class DuplicateIdValidationTests(SimpleTestCase):
    """validate_pack catches duplicate IDs that would cause silent overwrites."""

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_duplicate_component_ids_are_errors(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "dup-pack", slug="dup-pack")

            comp_data = {
                "components": [
                    {"id": "web-server", "name": "Web Server", "category": "process"},
                    {
                        "id": "web-server",
                        "name": "Web Server Copy",
                        "category": "process",
                    },
                ]
            }
            (pack_dir / "components.yaml").write_text(yaml.safe_dump(comp_data))

            result = validate_pack(pack_dir)

            dup_errors = [
                e for e in result.errors if "Duplicate component id" in e.message
            ]
            self.assertEqual(len(dup_errors), 1)
            self.assertIn("web-server", dup_errors[0].message)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_duplicate_threat_ids_are_errors(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "dup-pack", slug="dup-pack")

            threat_data = {
                "threats": [
                    {"id": "sql-injection", "name": "SQL Injection"},
                    {"id": "sql-injection", "name": "SQL Injection 2"},
                ]
            }
            (pack_dir / "threats.yaml").write_text(yaml.safe_dump(threat_data))

            result = validate_pack(pack_dir)

            dup_errors = [
                e for e in result.errors if "Duplicate threat id" in e.message
            ]
            self.assertEqual(len(dup_errors), 1)
            self.assertIn("sql-injection", dup_errors[0].message)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_duplicate_countermeasure_ids_are_errors(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "dup-pack", slug="dup-pack")

            cm_data = {
                "countermeasures": [
                    {
                        "slug": "mfa",
                        "name": "MFA",
                        "control_type": "preventive",
                        "cost": "low",
                    },
                    {
                        "slug": "mfa",
                        "name": "MFA duplicate",
                        "control_type": "preventive",
                        "cost": "low",
                    },
                ]
            }
            (pack_dir / "countermeasures.yaml").write_text(yaml.safe_dump(cm_data))

            result = validate_pack(pack_dir)

            dup_errors = [
                e for e in result.errors if "Duplicate countermeasure id" in e.message
            ]
            self.assertEqual(len(dup_errors), 1)
            self.assertIn("mfa", dup_errors[0].message)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_duplicate_framework_section_codes_are_errors(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pack_dir = base / "fw-pack"
            pack_dir.mkdir()

            pack_yaml = {
                "pack": {
                    "slug": "fw-pack",
                    "name": "fw-pack",
                    "version": "1.0.0",
                    "pack_type": "compliance",
                },
                "frameworks": [
                    {
                        "slug": "test-fw",
                        "name": "Test Framework",
                        "requirements": [
                            {"section_code": "1.1", "description": "First"},
                            {"section_code": "1.1", "description": "Duplicate"},
                        ],
                    }
                ],
            }
            (pack_dir / "pack.yaml").write_text(yaml.safe_dump(pack_yaml))

            result = validate_pack(pack_dir)

            dup_errors = [
                e for e in result.errors if "Duplicate section_code" in e.message
            ]
            self.assertEqual(len(dup_errors), 1)
            self.assertIn("1.1", dup_errors[0].message)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_duplicate_taxonomy_external_ids_are_errors(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "tax-pack", slug="tax-pack")

            tax_data = {
                "taxonomies": [
                    {
                        "slug": "cwe",
                        "name": "CWE",
                        "entries": [
                            {"external_id": "CWE-79", "title": "XSS"},
                            {"external_id": "CWE-79", "title": "XSS duplicate"},
                        ],
                    }
                ]
            }
            (pack_dir / "taxonomy.yaml").write_text(yaml.safe_dump(tax_data))

            result = validate_pack(pack_dir)

            dup_errors = [
                e for e in result.errors if "Duplicate external_id" in e.message
            ]
            self.assertEqual(len(dup_errors), 1)
            self.assertIn("CWE-79", dup_errors[0].message)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_unique_ids_pass_validation(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "clean-pack", slug="clean-pack")

            comp_data = {
                "components": [
                    {"id": "web-server", "name": "Web Server", "category": "process"},
                    {"id": "database", "name": "Database", "category": "datastore"},
                ]
            }
            (pack_dir / "components.yaml").write_text(yaml.safe_dump(comp_data))

            result = validate_pack(pack_dir)

            dup_errors = [e for e in result.errors if "Duplicate" in e.message]
            self.assertEqual(len(dup_errors), 0)


# =========================================================================
# Phase 3: Overlay section_code validation (issue #10)
# =========================================================================


class OverlaySectionCodeValidationTests(SimpleTestCase):
    """validate_pack checks overlay section_codes against framework requirements."""

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.compliance.models.StandardRequirement")
    @mock.patch("apps.compliance.models.StandardFramework")
    def test_invalid_section_code_is_error(
        self, mock_fw, mock_req, mock_lp, mock_taxonomy
    ):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        # Framework exists
        mock_framework_instance = mock.MagicMock()
        mock_fw.objects.filter.return_value.first.return_value = mock_framework_instance

        # Framework has requirements — but not the one we reference
        mock_req.objects.filter.return_value.values_list.return_value = ["1.1", "1.2"]

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "overlay-pack", slug="overlay-pack")

            joins_dir = pack_dir / "joins"
            joins_dir.mkdir()
            overlay_data = {
                "framework": "nist-csf",
                "mappings": [
                    {"countermeasure": "mfa", "requirements": ["1.1", "BOGUS"]},
                ],
            }
            (joins_dir / "countermeasures-nist-csf.yaml").write_text(
                yaml.safe_dump(overlay_data)
            )

            result = validate_pack(pack_dir)

            section_errors = [
                e
                for e in result.errors
                if "section_code" in e.message and "BOGUS" in e.message
            ]
            self.assertEqual(len(section_errors), 1)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.compliance.models.StandardFramework")
    def test_missing_framework_is_warning(self, mock_fw, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        # Framework does NOT exist
        mock_fw.objects.filter.return_value.first.return_value = None

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "overlay-pack", slug="overlay-pack")

            joins_dir = pack_dir / "joins"
            joins_dir.mkdir()
            overlay_data = {
                "framework": "nonexistent-fw",
                "mappings": [
                    {"countermeasure": "mfa", "requirements": ["1.1"]},
                ],
            }
            (joins_dir / "countermeasures-nonexistent-fw.yaml").write_text(
                yaml.safe_dump(overlay_data)
            )

            result = validate_pack(pack_dir)

            fw_warnings = [
                w
                for w in result.warnings
                if "nonexistent-fw" in w.message and "not found" in w.message
            ]
            self.assertEqual(len(fw_warnings), 1)
            # Should NOT be an error
            fw_errors = [e for e in result.errors if "nonexistent-fw" in e.message]
            self.assertEqual(len(fw_errors), 0)


# =========================================================================
# Phase 4: depends_on validation (issue #10)
# =========================================================================


class DependsOnValidationTests(SimpleTestCase):
    """validate_pack warns when depends_on references can't be found."""

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.packs.services.get_libraries_path")
    def test_missing_dependency_is_warning(
        self, mock_get_libraries_path, mock_lp, mock_taxonomy
    ):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mock_get_libraries_path.return_value = base

            pack_dir = _write_pack(
                base,
                "dep-pack",
                slug="dep-pack",
                depends_on=["nonexistent-dep"],
            )

            result = validate_pack(pack_dir)

            dep_warnings = [
                w
                for w in result.warnings
                if "nonexistent-dep" in w.message and "depends_on" in w.field
            ]
            self.assertEqual(len(dep_warnings), 1)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.packs.services.get_libraries_path")
    def test_found_dependency_no_warning(
        self, mock_get_libraries_path, mock_lp, mock_taxonomy
    ):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mock_get_libraries_path.return_value = base

            # Create the dependency pack on disk
            _write_pack(base, "stride-taxonomy", slug="stride-taxonomy")

            pack_dir = _write_pack(
                base,
                "dep-pack",
                slug="dep-pack",
                depends_on=["stride-taxonomy"],
            )

            result = validate_pack(pack_dir)

            dep_warnings = [
                w
                for w in result.warnings
                if "stride-taxonomy" in w.message and "depends_on" in w.field
            ]
            self.assertEqual(len(dep_warnings), 0)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.packs.services.get_libraries_path")
    def test_missing_dependency_is_not_error(
        self, mock_get_libraries_path, mock_lp, mock_taxonomy
    ):
        """Missing dependencies are warnings, not errors — import should still succeed."""
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mock_get_libraries_path.return_value = base

            pack_dir = _write_pack(
                base,
                "dep-pack",
                slug="dep-pack",
                depends_on=["ghost-pack"],
            )

            result = validate_pack(pack_dir)

            dep_errors = [e for e in result.errors if "ghost-pack" in e.message]
            self.assertEqual(len(dep_errors), 0)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.packs.services.get_libraries_path")
    def test_path_format_depends_on_resolves(
        self, mock_get_libraries_path, mock_lp, mock_taxonomy
    ):
        """depends_on with path-format strings (e.g. 'taxonomies/stride-taxonomy') should resolve."""
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mock_get_libraries_path.return_value = base

            # Create the dependency at the path
            _write_pack(base, "taxonomies/stride-taxonomy", slug="stride-taxonomy")

            pack_dir = _write_pack(
                base,
                "dep-pack",
                slug="dep-pack",
                depends_on=["taxonomies/stride-taxonomy"],
            )

            result = validate_pack(pack_dir)

            dep_warnings = [
                w
                for w in result.warnings
                if "stride-taxonomy" in w.message and "depends_on" in w.field
            ]
            self.assertEqual(len(dep_warnings), 0)


# =========================================================================
# Phase 5: Slug format validation (issue #10)
# =========================================================================


class SlugFormatValidationTests(SimpleTestCase):
    """validate_pack warns on non-conforming slug formats."""

    def test_is_valid_slug_accepts_good_slugs(self):
        self.assertTrue(_is_valid_slug("aws"))
        self.assertTrue(_is_valid_slug("aws-core"))
        self.assertTrue(_is_valid_slug("base-stride"))
        self.assertTrue(_is_valid_slug("a1-b2-c3"))

    def test_is_valid_slug_rejects_bad_slugs(self):
        self.assertFalse(_is_valid_slug("AWS"))
        self.assertFalse(_is_valid_slug("my_pack"))
        self.assertFalse(_is_valid_slug("my.pack"))
        self.assertFalse(_is_valid_slug("-leading-hyphen"))
        self.assertFalse(_is_valid_slug("trailing-hyphen-"))
        self.assertFalse(_is_valid_slug("double--hyphen"))
        self.assertFalse(_is_valid_slug(""))

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_bad_pack_slug_is_warning(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "Bad_Pack", slug="Bad_Pack")

            result = validate_pack(pack_dir)

            slug_warnings = [
                w
                for w in result.warnings
                if "Bad_Pack" in w.message and "slug" in w.field
            ]
            self.assertEqual(len(slug_warnings), 1)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_bad_component_id_is_warning(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "slug-pack", slug="slug-pack")

            comp_data = {
                "components": [
                    {"id": "aws_lambda", "name": "Lambda", "category": "process"},
                ]
            }
            (pack_dir / "components.yaml").write_text(yaml.safe_dump(comp_data))

            result = validate_pack(pack_dir)

            slug_warnings = [
                w
                for w in result.warnings
                if "aws_lambda" in w.message and "slug format" in w.message
            ]
            self.assertEqual(len(slug_warnings), 1)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_good_slug_no_warning(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "good-pack", slug="good-pack")

            comp_data = {
                "components": [
                    {"id": "web-server", "name": "Web Server", "category": "process"},
                ]
            }
            (pack_dir / "components.yaml").write_text(yaml.safe_dump(comp_data))

            result = validate_pack(pack_dir)

            slug_warnings = [w for w in result.warnings if "slug format" in w.message]
            self.assertEqual(len(slug_warnings), 0)


# =========================================================================
# Phase 1: ImportResult warnings (issue #10)
# =========================================================================


class ImportResultWarningsTests(SimpleTestCase):
    """ImportResult exposes warnings field in dataclass and to_dict()."""

    def test_import_result_has_warnings_field(self):
        result = ImportResult(
            success=True,
            pack_slug="test",
            pack_name="Test",
            version="1.0.0",
            message="OK",
            warnings=["something was skipped"],
        )
        self.assertEqual(result.warnings, ["something was skipped"])

    def test_import_result_to_dict_includes_warnings(self):
        result = ImportResult(
            success=True,
            pack_slug="test",
            pack_name="Test",
            version="1.0.0",
            message="OK",
            warnings=["warn1", "warn2"],
        )
        d = result.to_dict()
        self.assertIn("warnings", d)
        self.assertEqual(d["warnings"], ["warn1", "warn2"])

    def test_import_result_warnings_default_empty(self):
        result = ImportResult(
            success=True,
            pack_slug="test",
            pack_name="Test",
            version="1.0.0",
            message="OK",
        )
        self.assertEqual(result.warnings, [])
        self.assertEqual(result.to_dict()["warnings"], [])


class GetLibrariesPathTests(SimpleTestCase):
    """The pack sources come from settings.LIBRARIES_PATH and nowhere else.

    The path used to be guessed from BASE_DIR with a fallback, which found nothing
    under a container that mounts the directory elsewhere. Every catalog then came
    up empty and looked like an unseeded database.
    """

    @override_settings(LIBRARIES_PATH="/mounted/elsewhere")
    def test_reads_the_configured_location(self):
        self.assertEqual(get_libraries_path(), Path("/mounted/elsewhere/packs"))

    @override_settings(LIBRARIES_PATH=Path("/mounted/elsewhere"))
    def test_accepts_a_path_as_well_as_a_string(self):
        self.assertEqual(get_libraries_path(), Path("/mounted/elsewhere/packs"))

    @override_settings(LIBRARIES_PATH="/nowhere/at/all")
    def test_does_not_fall_back_when_the_location_is_missing(self):
        """A configured path that does not exist is returned, not searched around.

        Callers report the path they were given, which is the only thing that tells
        an operator which mount is wrong.
        """
        libraries_path = get_libraries_path()
        self.assertFalse(libraries_path.exists())
        self.assertEqual(libraries_path, Path("/nowhere/at/all/packs"))
