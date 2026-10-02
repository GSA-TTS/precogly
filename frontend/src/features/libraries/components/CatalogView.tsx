import { useState, useMemo, useEffect } from 'react'
import { Package, Search } from 'lucide-react'
import { toast } from 'sonner'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { PreviewPackDialog } from './PreviewPackDialog'
import { ImportPackDialog } from './ImportPackDialog'
import { ValidationWarningsDialog } from './ValidationWarningsDialog'
import { CatalogPackCard } from './CatalogPackCard'
import {
  useAvailablePacksFromSource,
  useImportSinglePack,
  useValidatePack,
  usePacks,
} from '@/features/libraries/api/packs'
import type { PackFilters, ValidationResult } from '@/features/libraries/types/packs'
import { useWorkspace } from '@/contexts/WorkspaceContext'
import type { UnifiedPack } from './unified-pack'

export function CatalogView() {
  const { isSecurityTeam } = useWorkspace()
  const [filters, setFilters] = useState<PackFilters>({})
  const [searchInput, setSearchInput] = useState('')
  const [previewPackId, setPreviewPackId] = useState<number | null>(null)
  const [previewPackPath, setPreviewPackPath] = useState<string | null>(null)
  const [previewDialogOpen, setPreviewDialogOpen] = useState(false)
  const [importingSlug, setImportingSlug] = useState<string | null>(null)
  const [installDialogPack, setInstallDialogPack] = useState<UnifiedPack | null>(null)
  // Validation dialog state
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null)
  const [validationDialogOpen, setValidationDialogOpen] = useState(false)
  const [validationPackSlug, setValidationPackSlug] = useState<string | null>(null)

  const { data: dbPacks, isLoading: isLoadingDb } = usePacks(filters)
  const { data: sourcePacks, isLoading: isLoadingSource } = useAvailablePacksFromSource()

  const importMutation = useImportSinglePack()
  const validateMutation = useValidatePack()
  const [validatingSlug, setValidatingSlug] = useState<string | null>(null)

  // Debounced search: update filters after user stops typing
  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters((prev) => ({ ...prev, search: searchInput || undefined }))
    }, 300)
    return () => clearTimeout(timer)
  }, [searchInput])

  // Category labels derived from the first segment of relativePath
  const categoryLabels: Record<string, string> = {
    taxonomies: 'Taxonomies',
    standards: 'Standards',
    'threat-libraries': 'Threat Libraries',
  }

  const unifiedPacks = useMemo(() => {
    const packs: UnifiedPack[] = []
    const seenSlugs = new Set<string>()

    if (sourcePacks?.packs) {
      for (const sp of sourcePacks.packs) {
        const dbPack = dbPacks?.find((p) => p.slug === sp.slug)
        packs.push({
          slug: sp.slug,
          name: sp.name,
          description: sp.description,
          version: sp.version,
          packType: sp.packType,
          tags: sp.tags,
          relativePath: sp.relativePath,
          componentCount: sp.componentCount,
          threatCount: sp.threatCount,
          isInDatabase: sp.isInDatabase,
          isImported: sp.isInDatabase || (dbPack?.isImported ?? false),
          databaseId: dbPack?.id ?? null,
          dependsOn: sp.dependsOn ?? [],
        })
        seenSlugs.add(sp.slug)
      }
    }

    if (dbPacks) {
      for (const dbPack of dbPacks) {
        if (!seenSlugs.has(dbPack.slug)) {
          packs.push({
            slug: dbPack.slug,
            name: dbPack.name,
            description: dbPack.description,
            version: dbPack.version,
            packType: dbPack.packType,
            tags: dbPack.tags,
            relativePath: '',
            componentCount: 0,
            threatCount: 0,
            isInDatabase: true,
            isImported: dbPack.isImported,
            databaseId: dbPack.id,
            dependsOn: [],
          })
        }
      }
    }

    let filtered = packs
    if (filters.search) {
      const search = filters.search.toLowerCase()
      filtered = packs.filter(
        (p) =>
          p.name.toLowerCase().includes(search) ||
          p.description.toLowerCase().includes(search) ||
          p.tags.some((t) => t.toLowerCase().includes(search))
      )
    }
    if (filters.category) {
      filtered = filtered.filter((p) => {
        const firstSegment = p.relativePath.split('/')[0]
        return firstSegment === filters.category
      })
    }
    return filtered
  }, [sourcePacks, dbPacks, filters])

  const handleFilterChange = (key: keyof PackFilters, value: string) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value === 'all' ? undefined : value,
    }))
  }

  const handleImportClick = (pack: UnifiedPack) => {
    // Open the import dialog to show overlay options
    setInstallDialogPack(pack)
  }

  const handleImportConfirm = async (
    pack: UnifiedPack,
    selectedOverlays: string[] | null
  ) => {
    setImportingSlug(pack.slug)
    setInstallDialogPack(null)
    try {
      const result = await importMutation.mutateAsync({
        slug: pack.slug,
        force: pack.isInDatabase,
        selectedOverlays,
      })
      if (result.warnings && result.warnings.length > 0) {
        toast.warning(
          `Imported ${pack.name} with ${result.warnings.length} warning(s)`,
          {
            description:
              result.warnings[0] +
              (result.warnings.length > 1
                ? ` (+${result.warnings.length - 1} more)`
                : ''),
          }
        )
      } else {
        toast.success(`Successfully imported ${pack.name}`)
      }
    } catch (error: unknown) {
      const errorObj = error as { status?: number; data?: unknown }
      const errorData = errorObj?.data as Record<string, unknown> | undefined
      // Show validation dialog for both 422 (warnings) and 400 (errors from validation)
      if ((errorObj?.status === 422 || errorObj?.status === 400) && errorData && 'warningCount' in errorData) {
        setValidationResult(errorData as unknown as ValidationResult)
        setValidationPackSlug(pack.slug)

        setValidationDialogOpen(true)
        return
      }
      const message = errorData?.message as string | undefined
      toast.error(message || 'Import failed')
    } finally {
      setImportingSlug(null)
    }
  }

  const handlePreview = (pack: UnifiedPack) => {
    if (pack.databaseId) {
      setPreviewPackId(pack.databaseId)
      setPreviewPackPath(null)
    } else {
      setPreviewPackId(null)
      setPreviewPackPath(pack.relativePath)
    }
    setPreviewDialogOpen(true)
  }

  const handleValidate = async (pack: UnifiedPack) => {
    setValidatingSlug(pack.slug)
    try {
      const result = await validateMutation.mutateAsync({ slug: pack.slug })
      if (result.errorCount > 0 || result.warningCount > 0) {
        setValidationResult(result)
        setValidationPackSlug(pack.slug)
        setValidationDialogOpen(true)
      } else {
        toast.success('Validation passed — no issues found')
      }
    } catch {
      toast.error('Validation request failed')
    } finally {
      setValidatingSlug(null)
    }
  }

  const isLoading = isLoadingDb || isLoadingSource

  return (
    <div className="space-y-6">
      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search packs..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select
          value={filters.category ?? 'all'}
          onValueChange={(value) => handleFilterChange('category', value)}
        >
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            {Object.entries(categoryLabels).map(([key, label]) => (
              <SelectItem key={key} value={key}>
                {label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Result count */}
      {!isLoading && (
        <p className="text-sm text-muted-foreground">
          Showing {unifiedPacks.length} pack{unifiedPacks.length !== 1 ? 's' : ''}
        </p>
      )}

      {/* Pack Grid */}
      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-48 bg-muted animate-pulse rounded-lg" />
          ))}
        </div>
      ) : unifiedPacks.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {unifiedPacks.map((pack) => (
            <CatalogPackCard
              key={pack.slug}
              pack={pack}
              onImport={handleImportClick}
              onPreview={handlePreview}
              onValidate={handleValidate}
              isImporting={importingSlug === pack.slug}
              isValidating={validatingSlug === pack.slug}
              isSecurityTeam={isSecurityTeam}
            />
          ))}
        </div>
      ) : (
        <div className="text-center py-12">
          <Package className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
          <h3 className="text-lg font-medium mb-2">No packs found</h3>
          <p className="text-muted-foreground">
            {filters.search || filters.category
              ? 'Try adjusting your search or filters.'
              : 'No library packs are available yet.'}
          </p>
        </div>
      )}

      <PreviewPackDialog
        packId={previewPackId}
        packPath={previewPackPath}
        open={previewDialogOpen}
        onOpenChange={setPreviewDialogOpen}
      />

      <ImportPackDialog
        pack={installDialogPack}
        open={installDialogPack !== null}
        onOpenChange={(open) => !open && setInstallDialogPack(null)}
        onConfirm={handleImportConfirm}
      />

      <ValidationWarningsDialog
        validationResult={validationResult}
        open={validationDialogOpen}
        onOpenChange={(open) => {
          setValidationDialogOpen(open)
          if (!open) {
            setValidationResult(null)
            setValidationPackSlug(null)
          }
        }}
        onImportAnyway={
          validationPackSlug
            ? async () => {
                try {
                  const result = await importMutation.mutateAsync({
                    slug: validationPackSlug,
                    force: true,
                    skipValidation: true,
                  })
                  setValidationDialogOpen(false)
                  setValidationResult(null)
                  setValidationPackSlug(null)
                  if (result.warnings && result.warnings.length > 0) {
                    toast.warning(
                      `Imported with ${result.warnings.length} warning(s)`,
                      { description: result.warnings[0] }
                    )
                  } else {
                    toast.success(`Successfully imported ${result.packName}`)
                  }
                } catch {
                  toast.error('Import failed')
                }
              }
            : undefined
        }
        isImporting={importMutation.isPending}
      />
    </div>
  )
}
