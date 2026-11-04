/**
 * Guided guest-mode walkthrough (FIPS 199 -> Architecture Pack -> Control Baseline)
 * for GSA-TTS/TTSE-petrified-forest-sspp#96.
 */

import type { DeserializedFile } from './cyclonedx-guest'
import { deserializeCycloneDxToGuest } from './cyclonedx-guest'

export type FipsImpact = 'low' | 'moderate' | 'high'

export interface Nist80060InfoType {
  id: string
  code: string
  name: string
  category: string
  defaultConfidentiality: FipsImpact
  defaultIntegrity: FipsImpact
  defaultAvailability: FipsImpact
}

export interface SelectedInfoTypeImpact {
  id: string
  confidentiality: FipsImpact
  integrity: FipsImpact
  availability: FipsImpact
}

export interface Fips199Categorization {
  confidentiality: FipsImpact
  integrity: FipsImpact
  availability: FipsImpact
  overall: FipsImpact
}

export const NIST_800_60_INFO_TYPES: Nist80060InfoType[] = [
  {
    id: 'D.14.1',
    code: 'D.14.1',
    name: 'Health Care Delivery Services',
    category: 'Health',
    defaultConfidentiality: 'moderate',
    defaultIntegrity: 'moderate',
    defaultAvailability: 'moderate',
  },
  {
    id: 'D.8.1',
    code: 'D.8.1',
    name: 'Criminal Investigation & Law Enforcement',
    category: 'Law Enforcement',
    defaultConfidentiality: 'high',
    defaultIntegrity: 'moderate',
    defaultAvailability: 'moderate',
  },
  {
    id: 'C.2.4.1',
    code: 'C.2.4.1',
    name: 'Tax & Revenue Collection / Financial Management',
    category: 'Financial & Tax',
    defaultConfidentiality: 'moderate',
    defaultIntegrity: 'moderate',
    defaultAvailability: 'low',
  },
  {
    id: 'C.2.8.1',
    code: 'C.2.8.1',
    name: 'Procurement and Acquisition (FPDF / Federal Contracting)',
    category: 'Acquisition',
    defaultConfidentiality: 'moderate',
    defaultIntegrity: 'moderate',
    defaultAvailability: 'low',
  },
  {
    id: 'C.3.5.1',
    code: 'C.3.5.1',
    name: 'General Administrative & Public Information Dissemination',
    category: 'General Administrative',
    defaultConfidentiality: 'low',
    defaultIntegrity: 'moderate',
    defaultAvailability: 'low',
  },
  {
    id: 'C.3.2.1',
    code: 'C.3.2.1',
    name: 'Identity, Credential, and Access Management (ICAM)',
    category: 'Security & Identity',
    defaultConfidentiality: 'high',
    defaultIntegrity: 'high',
    defaultAvailability: 'moderate',
  },
]

const IMPACT_RANK: Record<FipsImpact, number> = {
  low: 1,
  moderate: 2,
  high: 3,
}

function maxImpact(values: FipsImpact[]): FipsImpact {
  let best: FipsImpact = 'low'
  for (const v of values) {
    if (IMPACT_RANK[v] > IMPACT_RANK[best]) {
      best = v
    }
  }
  return best
}

export function computeFips199HighWaterMark(
  selections: SelectedInfoTypeImpact[]
): Fips199Categorization {
  if (selections.length === 0) {
    return {
      confidentiality: 'low',
      integrity: 'low',
      availability: 'low',
      overall: 'low',
    }
  }
  const confidentiality = maxImpact(selections.map((s) => s.confidentiality))
  const integrity = maxImpact(selections.map((s) => s.integrity))
  const availability = maxImpact(selections.map((s) => s.availability))
  const overall = maxImpact([confidentiality, integrity, availability])
  return { confidentiality, integrity, availability, overall }
}

export interface ArchitecturePatternOption {
  id: string
  label: string
  packSlug: string
  description: string
  components: {
    id: string
    label: string
    type: 'process' | 'datastore' | 'humanActor' | 'systemActor'
    zone: 'internet' | 'dmz' | 'app' | 'data'
    librarySlug: string
  }[]
  inheritedControls: string[]
  sharedControls: Record<string, string>
  candidateThreats: { id: string; name: string; description: string; controlId: string }[]
}

export const ARCHITECTURE_PATTERNS: ArchitecturePatternOption[] = [
  {
    id: 'cloudgov-pages',
    label: 'cloud.gov Pages (Static Site)',
    packSlug: 'cloudgov-paas',
    description: '100% platform-managed static site hosting on GSA Pages / cloud.gov CDN.',
    components: [
      { id: 'pages-cdn', label: 'cloud.gov CDN', type: 'process', zone: 'dmz', librarySlug: 'cloudgov-paas/cloudgov-cdn' },
      { id: 'pages-site', label: 'GSA Pages Static Site', type: 'process', zone: 'app', librarySlug: 'cloudgov-paas/cloudgov-pages' },
    ],
    inheritedControls: ['AC-2', 'AC-3', 'AC-17', 'AU-2', 'AU-6', 'CM-2', 'CM-6', 'IA-2', 'SC-7', 'SC-8', 'SC-28', 'SI-2', 'SI-4'],
    sharedControls: {
      'SR-3': 'Maintain dependency lockfiles and automated vulnerability scanning in the source repository.',
    },
    candidateThreats: [
      { id: 't-pages-supply-chain', name: 'Static build dependency compromise', description: 'Compromised npm package injected during static site build.', controlId: 'SR-3' },
    ],
  },
  {
    id: 'cloudgov-paas',
    label: 'cloud.gov (PaaS)',
    packSlug: 'cloudgov-paas',
    description: '12-factor web application on Cloud Foundry with managed RDS and S3.',
    components: [
      { id: 'cg-cdn', label: 'cloud.gov Router / CDN', type: 'process', zone: 'dmz', librarySlug: 'cloudgov-paas/cloudgov-cdn' },
      { id: 'cg-app', label: 'cloud.gov Application', type: 'process', zone: 'app', librarySlug: 'cloudgov-paas/cloudgov-apps' },
      { id: 'cg-rds', label: 'cloud.gov Managed RDS', type: 'datastore', zone: 'data', librarySlug: 'cloudgov-paas/cloudgov-rds' },
    ],
    inheritedControls: ['AC-17', 'AU-2', 'CM-2', 'SC-7', 'SC-8', 'SC-28', 'SI-2'],
    sharedControls: {
      'AC-2': 'Provision application roles and integrate with GSA SSO / Login.gov.',
      'AC-3': 'Enforce role-based access control on all application endpoints.',
      'AU-6': 'Review application-level audit events weekly.',
      'IA-2': 'Require phishing-resistant MFA (PIV / WebAuthn) via federated IdP.',
      'SI-4': 'Configure application error alerting and log forwarding.',
      'SR-3': 'Pin and scan application dependencies in CI/CD.',
    },
    candidateThreats: [
      { id: 't-cg-authz', name: 'Broken object-level authorization on API route', description: 'Authenticated user accesses another tenant record due to missing RBAC check.', controlId: 'AC-3' },
      { id: 't-cg-supply-chain', name: 'CI/CD dependency supply-chain compromise', description: 'Unpinned third-party dependency introduces malicious code.', controlId: 'SR-3' },
    ],
  },
  {
    id: 'fcs-mcaas',
    label: 'MCaaS (FCS / Databricks)',
    packSlug: 'fcs-mcaas',
    description: 'GSA FCS Managed Cloud as a Service with Databricks workspace and managed S3.',
    components: [
      { id: 'mcaas-vpcaas', label: 'FCS VPCaaS Boundary', type: 'process', zone: 'dmz', librarySlug: 'fcs-mcaas/mcaas-vpcaas' },
      { id: 'mcaas-dbx', label: 'FCS Databricks Workspace', type: 'process', zone: 'app', librarySlug: 'fcs-mcaas/mcaas-databricks' },
      { id: 'mcaas-s3', label: 'FCS Managed S3 Data Lake', type: 'datastore', zone: 'data', librarySlug: 'fcs-mcaas/mcaas-data' },
    ],
    inheritedControls: ['SC-7', 'SC-28'],
    sharedControls: {
      'AC-2': 'Configure SCIM identity sync and Unity Catalog group entitlements.',
      'AC-3': 'Enforce Unity Catalog table ACLs and row/column security.',
      'AC-17': 'Restrict workspace administrative API access to authorized Bastion/VPN origins.',
      'AU-2': 'Enable Databricks diagnostic audit log delivery to central SIEM.',
      'AU-6': 'Audit privileged service principal and Unity Catalog grant changes.',
      'CM-2': 'Manage workspace configuration and cluster policies via Terraform.',
      'IA-2': 'Enforce SAML/OIDC federation with PIV MFA.',
      'SC-8': 'Enforce TLS 1.2+ on all external data ingestion and Delta Sharing links.',
      'SI-2': 'Maintain container/runtime version baselines and remediate CVEs within SLA.',
    },
    candidateThreats: [
      { id: 't-mcaas-sp', name: 'Over-privileged deployer service principal blast radius', description: 'Single service principal token compromised in CI pivots across workspaces.', controlId: 'AC-2' },
      { id: 't-mcaas-s3', name: 'Unmonitored bulk data exfiltration from S3', description: 'Authorized token reads sensitive Delta tables without access-log alerting.', controlId: 'AU-6' },
      { id: 't-mcaas-audit', name: 'Disabled or delayed workspace audit log delivery', description: 'Attacker disables diagnostic log forwarding to evade detection.', controlId: 'AU-2' },
    ],
  },
  {
    id: 'raw-aws',
    label: 'Raw AWS (gsa-overlay-aws)',
    packSlug: 'gsa-overlay-aws',
    description: 'Customer-managed AWS GovCloud VPC, compute, and storage with minimal inheritance.',
    components: [
      { id: 'aws-alb', label: 'AWS Application Load Balancer', type: 'process', zone: 'dmz', librarySlug: 'gsa-overlay-aws/alb' },
      { id: 'aws-ecs', label: 'AWS Compute Service', type: 'process', zone: 'app', librarySlug: 'gsa-overlay-aws/ecs' },
      { id: 'aws-s3', label: 'Amazon S3 Bucket', type: 'datastore', zone: 'data', librarySlug: 'gsa-overlay-aws/s3' },
    ],
    inheritedControls: [],
    sharedControls: {
      'AC-2': 'Manage IAM roles, identity federation, and account lifecycle.',
      'SC-7': 'Configure VPC security groups, NACLs, and egress filtering.',
      'SC-8': 'Enforce ACM TLS certificates and HTTPS listeners.',
      'SC-28': 'Enable KMS customer-managed key encryption on S3 and EBS.',
    },
    candidateThreats: [
      { id: 't-aws-s3', name: 'Misconfigured S3 bucket policy or IAM role', description: 'Overly permissive IAM policy exposes bucket objects.', controlId: 'AC-3' },
      { id: 't-aws-imds', name: 'SSRF credential theft via instance metadata', description: 'IMDSv1 fallback allows token theft from compute node.', controlId: 'IA-2' },
    ],
  },
  {
    id: 'gcp',
    label: 'GCP (gsa-overlay-gcp)',
    packSlug: 'gsa-overlay-gcp',
    description: 'Google Cloud Platform workload with Cloud Run / GKE and Cloud Storage.',
    components: [
      { id: 'gcp-run', label: 'Google Cloud Run Service', type: 'process', zone: 'app', librarySlug: 'gsa-overlay-gcp/cloud-run' },
      { id: 'gcp-gcs', label: 'Google Cloud Storage', type: 'datastore', zone: 'data', librarySlug: 'gsa-overlay-gcp/gcs' },
    ],
    inheritedControls: [],
    sharedControls: {
      'AC-2': 'Configure Cloud IAM workforce identity federation and service accounts.',
      'SC-7': 'Enforce VPC Service Controls perimeter and Cloud Armor policies.',
    },
    candidateThreats: [
      { id: 't-gcp-sa', name: 'Long-lived service account key leakage', description: 'Exported JSON service account key used from unauthorized network.', controlId: 'IA-2' },
    ],
  },
  {
    id: 'azure',
    label: 'Azure (gsa-overlay-azure)',
    packSlug: 'gsa-overlay-azure',
    description: 'Microsoft Azure Government workload with App Service and Azure SQL / Storage.',
    components: [
      { id: 'az-app', label: 'Azure App Service', type: 'process', zone: 'app', librarySlug: 'gsa-overlay-azure/app-service' },
      { id: 'az-sql', label: 'Azure SQL Database', type: 'datastore', zone: 'data', librarySlug: 'gsa-overlay-azure/sql' },
    ],
    inheritedControls: [],
    sharedControls: {
      'AC-2': 'Configure Entra ID enterprise application and conditional access.',
      'SC-7': 'Configure Azure Virtual Network integration and private endpoints.',
    },
    candidateThreats: [
      { id: 't-az-mi', name: 'Over-scoped managed identity role assignment', description: 'Subscription-wide Contributor role assigned to workload identity.', controlId: 'AC-3' },
    ],
  },
]

export interface BaselineControlSpec {
  id: string
  name: string
  baselines: FipsImpact[]
}

export const BASELINE_CONTROLS: BaselineControlSpec[] = [
  { id: 'AC-2', name: 'Account Management', baselines: ['low', 'moderate', 'high'] },
  { id: 'AC-3', name: 'Access Enforcement', baselines: ['low', 'moderate', 'high'] },
  { id: 'AC-17', name: 'Remote Access', baselines: ['low', 'moderate', 'high'] },
  { id: 'AU-2', name: 'Event Logging', baselines: ['low', 'moderate', 'high'] },
  { id: 'AU-6', name: 'Audit Record Review, Analysis, and Reporting', baselines: ['low', 'moderate', 'high'] },
  { id: 'CM-2', name: 'Baseline Configuration', baselines: ['low', 'moderate', 'high'] },
  { id: 'CM-6', name: 'Configuration Settings', baselines: ['low', 'moderate', 'high'] },
  { id: 'IA-2', name: 'Identification and Authentication (Organizational Users)', baselines: ['low', 'moderate', 'high'] },
  { id: 'SC-7', name: 'Boundary Protection', baselines: ['low', 'moderate', 'high'] },
  { id: 'SC-8', name: 'Transmission Confidentiality and Integrity', baselines: ['moderate', 'high'] },
  { id: 'SC-28', name: 'Protection of Information at Rest', baselines: ['moderate', 'high'] },
  { id: 'SI-2', name: 'Flaw Remediation', baselines: ['low', 'moderate', 'high'] },
  { id: 'SI-4', name: 'System Monitoring', baselines: ['low', 'moderate', 'high'] },
  { id: 'SR-3', name: 'Supply Chain Controls and Processes', baselines: ['moderate', 'high'] },
  { id: 'CP-9(1)', name: 'System Backup | Testing for Reliability and Integrity', baselines: ['high'] },
]

export type ControlCoverageState = 'inherited' | 'shared' | 'gap'

export interface EvaluatedBaselineControl {
  id: string
  name: string
  state: ControlCoverageState
  guidance: string
  providingPacks: string[]
}

export function evaluateControlBaseline(
  baseline: FipsImpact,
  selectedPatternIds: string[]
): EvaluatedBaselineControl[] {
  const patterns = ARCHITECTURE_PATTERNS.filter((p) => selectedPatternIds.includes(p.id))
  const controls = BASELINE_CONTROLS.filter((c) => c.baselines.includes(baseline))
  return controls.map((ctrl) => {
    const inheritedBy = patterns
      .filter((p) => p.inheritedControls.includes(ctrl.id))
      .map((p) => p.packSlug)
    const sharedEntries = patterns
      .filter((p) => p.sharedControls[ctrl.id])
      .map((p) => ({ pack: p.packSlug, text: p.sharedControls[ctrl.id] }))

    if (inheritedBy.length > 0 && sharedEntries.length === 0) {
      return {
        id: ctrl.id,
        name: ctrl.name,
        state: 'inherited',
        guidance: `100% inherited from ${inheritedBy.join(', ')}.`,
        providingPacks: inheritedBy,
      }
    }
    if (sharedEntries.length > 0) {
      return {
        id: ctrl.id,
        name: ctrl.name,
        state: 'shared',
        guidance: sharedEntries.map((e) => `[${e.pack}] ${e.text}`).join(' '),
        providingPacks: sharedEntries.map((e) => e.pack),
      }
    }
    return {
      id: ctrl.id,
      name: ctrl.name,
      state: 'gap',
      guidance: `Unaddressed in selected architecture for ${baseline.toUpperCase()} baseline — requires customer implementation.`,
      providingPacks: [],
    }
  })
}

export interface WalkthroughConfig {
  systemName: string
  systemDescription: string
  infoTypes: SelectedInfoTypeImpact[]
  patternIds: string[]
  selectedThreatIds: string[]
}

export function buildWalkthroughCycloneDxJson(config: WalkthroughConfig): string {
  const fips = computeFips199HighWaterMark(config.infoTypes)
  const controls = evaluateControlBaseline(fips.overall, config.patternIds)
  const patterns = ARCHITECTURE_PATTERNS.filter((p) => config.patternIds.includes(p.id))

  const zones = [
    { id: 'zone-internet', ref: 'zone-zone-internet', name: 'External / Internet', level: 10, x: 40, y: 40 },
    { id: 'zone-dmz', ref: 'zone-zone-dmz', name: 'Edge / DMZ', level: 40, x: 340, y: 40 },
    { id: 'zone-app', ref: 'zone-zone-app', name: 'Application Tier', level: 70, x: 640, y: 40 },
    { id: 'zone-data', ref: 'zone-zone-data', name: 'Data Tier', level: 90, x: 940, y: 40 },
  ]

  const canvasNodes: Record<string, unknown>[] = zones.map((z) => ({
    id: z.id,
    type: 'trustZone',
    position: { x: z.x, y: z.y },
    data: {
      label: z.name,
      zone_type: 'trust',
      trust_level: z.level,
      bom_ref: z.ref,
    },
    style: { width: 260, height: 320 },
  }))

  canvasNodes.push({
    id: 'actor-user',
    type: 'humanActor',
    position: { x: 40, y: 80 },
    parent_id: 'zone-internet',
    data: {
      label: 'Authorized User',
      actor_type: 'user',
      bom_ref: 'asset-actor-user',
    },
  })

  const cdxAssets: Record<string, unknown>[] = [
    {
      'bom-ref': 'asset-actor-user',
      name: 'Authorized User',
      type: 'actor',
      zone: 'zone-zone-internet',
      properties: [
        { name: 'precogly:category', value: 'external_human_actor' },
        { name: 'precogly:actor-type', value: 'user' },
      ],
    },
  ]
  const cdxDataStores: Record<string, unknown>[] = []
  const componentRefs: string[] = []

  let idx = 0
  for (const pattern of patterns) {
    for (const comp of pattern.components) {
      idx += 1
      const zoneId = `zone-${comp.zone}`
      const zoneRef = `zone-zone-${comp.zone}`
      const isStore = comp.type === 'datastore'
      const bomRef = isStore ? `datastore-${comp.id}` : `asset-${comp.id}`
      componentRefs.push(bomRef)
      canvasNodes.push({
        id: comp.id,
        type: comp.type,
        position: { x: 30, y: 60 + (idx % 3) * 80 },
        parent_id: zoneId,
        data: {
          label: comp.label,
          bom_ref: bomRef,
          ...(isStore ? { data_store_type: 'sql' } : { kind: 'service' }),
        },
      })
      if (isStore) {
        cdxDataStores.push({
          'bom-ref': bomRef,
          name: comp.label,
          type: 'relational',
          zone: zoneRef,
          properties: [
            { name: 'precogly:library', value: comp.librarySlug },
            { name: 'precogly:data-store-type', value: 'sql' },
          ],
        })
      } else {
        cdxAssets.push({
          'bom-ref': bomRef,
          name: comp.label,
          type: 'service',
          zone: zoneRef,
          properties: [
            { name: 'precogly:category', value: 'process' },
            { name: 'precogly:library', value: comp.librarySlug },
          ],
        })
      }
    }
  }

  const cdxFlows: Record<string, unknown>[] = []
  const canvasEdges: Record<string, unknown>[] = []
  if (componentRefs.length > 0) {
    const firstCompId = patterns[0]?.components[0]?.id ?? 'actor-user'
    const firstBomRef = componentRefs[0]
    cdxFlows.push({
      'bom-ref': 'flow-https-ingress',
      name: 'HTTPS Ingress',
      type: 'data',
      source: 'asset-actor-user',
      destination: firstBomRef,
      encrypted: true,
      protocols: ['HTTPS'],
      authentication: ['token'],
    })
    canvasEdges.push({
      id: 'flow-https-ingress',
      type: 'dataFlow',
      source: 'actor-user',
      target: firstCompId,
      data: {
        label: 'HTTPS Ingress',
        flow_type: 'data',
        protocol: 'HTTPS',
        encrypted: true,
        authentication: ['token'],
        bom_ref: 'flow-https-ingress',
      },
    })
  }

  const cdxThreats: Record<string, unknown>[] = []
  const cdxScenarios: Record<string, unknown>[] = []
  const cdxControls: Record<string, unknown>[] = []
  const cdxRequirements = controls.map((c) => ({
    'bom-ref': `req-nist-${c.id.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
    identifier: c.id,
    title: c.name,
    text: c.guidance,
  }))

  let tNum = 1
  let cNum = 1
  const targetRef = componentRefs[0] ?? 'system-model-1'

  for (const ctrl of controls) {
    const reqRef = `req-nist-${ctrl.id.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
    const controlBomRef = `control-cm-${ctrl.id.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
    const mitigatedScenarios: string[] = []

    if (ctrl.state === 'gap') {
      const tRef = `threat-gap-${ctrl.id.toLowerCase()}`
      const sRef = `scenario-gap-${ctrl.id.toLowerCase()}`
      mitigatedScenarios.push(sRef)
      cdxThreats.push({
        'bom-ref': tRef,
        name: `Unaddressed ${ctrl.id} (${ctrl.name})`,
        description: ctrl.guidance,
        properties: [{ name: 'ctrl:id', value: ctrl.id }],
        mitigations: [controlBomRef],
      })
      cdxScenarios.push({
        'bom-ref': sRef,
        name: `Unaddressed ${ctrl.id} (${ctrl.name})`,
        threats: [tRef],
        description: ctrl.guidance,
        affectedAssets: [targetRef],
        riskScore: {
          level: fips.overall === 'high' ? 'high' : 'medium',
          methodology: { name: 'manual' },
        },
        properties: [
          { name: 'precogly:number', value: String(tNum++) },
          { name: 'precogly:threat-status', value: 'exposed' },
          { name: 'precogly:triage-status', value: 'open' },
        ],
      })
    }

    const cdxStatus =
      ctrl.state === 'inherited'
        ? 'platform'
        : ctrl.state === 'shared'
          ? 'recommended'
          : 'gap'

    cdxControls.push({
      'bom-ref': controlBomRef,
      name: `${ctrl.id} — ${ctrl.name}`,
      description: ctrl.guidance,
      category: 'preventive',
      status: cdxStatus,
      appliesTo: [targetRef],
      satisfies: [reqRef],
      properties: [
        { name: 'precogly:number', value: String(cNum++) },
        { name: 'precogly:control-functions', value: '["preventive"]' },
        { name: 'precogly:control-nature', value: 'technical' },
        ...(mitigatedScenarios.length > 0
          ? [{ name: 'precogly:mitigates', value: JSON.stringify(mitigatedScenarios) }]
          : []),
      ],
    })
  }

  for (const pattern of patterns) {
    for (const cand of pattern.candidateThreats) {
      if (!config.selectedThreatIds.includes(cand.id)) continue
      const tRef = `threat-pack-${cand.id}`
      const sRef = `scenario-pack-${cand.id}`
      cdxThreats.push({
        'bom-ref': tRef,
        name: cand.name,
        description: cand.description,
        properties: [{ name: 'ctrl:id', value: cand.controlId }],
      })
      cdxScenarios.push({
        'bom-ref': sRef,
        name: cand.name,
        threats: [tRef],
        description: cand.description,
        affectedAssets: [targetRef],
        riskScore: { level: 'high', methodology: { name: 'manual' } },
        properties: [
          { name: 'precogly:number', value: String(tNum++) },
          { name: 'precogly:threat-status', value: 'exposed' },
          { name: 'precogly:triage-status', value: 'open' },
        ],
      })
    }
  }

  const canvasPayload = {
    notation_style: 'yourdon',
    nodes: canvasNodes,
    edges: canvasEdges,
  }
  const encodedCanvas = btoa(unescape(encodeURIComponent(JSON.stringify(canvasPayload))))

  const doc = {
    specFormat: 'CycloneDX',
    specVersion: '2.0',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [
          {
            type: 'application',
            name: 'Precogly Guest Walkthrough',
            version: '2.0.0',
          },
        ],
      },
      component: {
        type: 'application',
        'bom-ref': 'system-model-1',
        name: config.systemName.trim() || 'Guided System Model',
        description: config.systemDescription.trim() || undefined,
        properties: [
          { name: 'precogly:criticality', value: fips.overall },
          { name: 'fips199:confidentiality', value: fips.confidentiality },
          { name: 'fips199:integrity', value: fips.integrity },
          { name: 'fips199:availability', value: fips.availability },
          { name: 'fips199:categorization', value: fips.overall },
        ],
      },
    },
    blueprints: [
      {
        'bom-ref': 'blueprint-1',
        name: config.systemName.trim() || 'Guided System Model',
        description: config.systemDescription.trim() || undefined,
        modelTypes: ['data-flow'],
        assets: cdxAssets,
        dataStores: cdxDataStores,
        zones: zones.map((z) => ({
          'bom-ref': z.ref,
          name: z.name,
          type: 'trust',
          properties: [{ name: 'precogly:trust-level', value: String(z.level) }],
        })),
        flows: cdxFlows,
        visualizations: [
          {
            'bom-ref': 'visualization-1',
            name: config.systemName.trim() || 'Guided System Model',
            type: { type: 'data-flow' },
            attachment: {
              mediaType: 'application/vnd.precogly.dfd+json',
              encoding: 'base64',
              content: encodedCanvas,
            },
            properties: [
              { name: 'precogly:diagram-type', value: 'level1' },
              { name: 'precogly:primary', value: 'true' },
            ],
          },
        ],
      },
    ],
    threats: {
      threats: cdxThreats,
      scenarios: cdxScenarios,
    },
    controls: cdxControls,
    definitions: {
      standards: [
        {
          'bom-ref': 'standard-nist-800-53-r5',
          name: 'NIST SP 800-53 Rev. 5',
          version: '5',
          requirements: cdxRequirements,
        },
      ],
    },
    properties: [
      { name: 'precogly:next-threat-number', value: String(tNum) },
      { name: 'precogly:next-countermeasure-number', value: String(cNum) },
    ],
  }

  return JSON.stringify(doc, null, 2)
}

export function jsonToSimpleYaml(value: unknown, indent = 0): string {
  const pad = '  '.repeat(indent)
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'boolean' || typeof value === 'number') return String(value)
  if (typeof value === 'string') {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]'
    return value
      .map((item) => {
        if (typeof item === 'object' && item !== null) {
          const rendered = jsonToSimpleYaml(item, indent + 1).trimStart()
          return `${pad}- ${rendered}`
        }
        return `${pad}- ${jsonToSimpleYaml(item, indent + 1)}`
      })
      .join('\n')
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).filter(
      ([, v]) => v !== undefined
    )
    if (entries.length === 0) return '{}'
    return entries
      .map(([k, v]) => {
        const key = /^[a-zA-Z0-9_]+$/.test(k) ? k : JSON.stringify(k)
        if (typeof v === 'object' && v !== null && !(Array.isArray(v) && v.length === 0)) {
          return `${pad}${key}:\n${jsonToSimpleYaml(v, indent + 1)}`
        }
        return `${pad}${key}: ${jsonToSimpleYaml(v, indent + 1)}`
      })
      .join('\n')
  }
  return String(value)
}

export function buildWalkthroughGuestState(config: WalkthroughConfig): {
  json: string
  yaml: string
  deserialized: DeserializedFile
} {
  const json = buildWalkthroughCycloneDxJson(config)
  const parsed = JSON.parse(json) as unknown
  const yaml = jsonToSimpleYaml(parsed) + '\n'
  const deserialized = deserializeCycloneDxToGuest(json)
  return { json, yaml, deserialized }
}
