export type ReportType = 'executive' | 'technical' | 'compliance' | 'full'

export interface ReportMetadata {
  name: string
  description: string
  criticality: string
  riskScoringMethod: string
  owningTeam: string | null
  createdBy: string | null
  createdAt: string | null
  updatedAt: string | null
  frameworks: Array<{
    name: string
    slug: string
    version: string
  }>
}

export interface ReportScope {
  description: string
  scopeLocked: boolean
  assumptions: Array<{
    id: string
    description: string
    validity: 'unconfirmed' | 'confirmed' | 'rejected'
    topics: string[]
  }>
  outOfScopeItems: Array<{
    id: number
    name: string
    reason: string
  }>
  referencedModels: Array<{
    id: string
    name: string
    relationType: string
  }>
}

export interface ReportArchitecture {
  dfds: Array<{
    id: string
    name: string
    diagramType: string
    isPrimary?: boolean
    nodeCount: number
    edgeCount: number
    canvasData?: { nodes?: unknown[]; edges?: unknown[]; notationStyle?: string }
  }>
  referenceImages: Array<{
    id: number
    filename: string
    description: string
  }>
  trustZones: Array<{
    id: number
    name: string
    trustLevel: number
    description: string
  }>
  trustBoundaries: Array<{
    id: number
    label: string
    zoneA: string
    zoneB: string
    description: string
  }>
}

export interface ReportDataAsset {
  id: number
  name: string
  description: string
  classification: string
  confidentiality: string
  integrity: string
  availability: string
  placements: Array<{
    componentName: string
    dataState: string
    volume: string
    encrypted: boolean
  }>
  inTransit: Array<{
    dataFlowLabel: string
    protectionMethod: string
    encryptionType: string
  }>
}

export interface ReportComponent {
  id: number
  name: string
  category: string
  componentType: string
  actorType: string
  provider: string
  trustZone: string | null
  description: string
}

export interface ReportComponents {
  processes: ReportComponent[]
  dataStores: ReportComponent[]
  humanActors: ReportComponent[]
  systemActors: ReportComponent[]
}

export interface ReportDataFlow {
  id: number
  label: string
  source: string | null
  destination: string | null
  protocol: string
  encrypted: boolean
  authenticated: boolean
  crossesTrustZone: boolean
  hasSensitiveData: boolean
}

export interface ReportComplianceStandard {
  frameworkName: string
  sectionCode: string
  sufficiency: string
}

export interface ReportCountermeasure {
  id: number
  countermeasureName: string
  controlFunctions: string[]
  controlNature: string
  status: string
  priority: string
  assignedOwnerEmail: string | null
  verifiedByEmail: string | null
  evidenceUrl: string
  isInherited: boolean
  inheritedFromComponentName: string | null
  inheritedFromZoneName: string | null
  complianceStandards?: ReportComplianceStandard[]
}

export interface ReportThreatTaxonomyEntry {
  taxonomySlug: string
  externalId: string
  title: string
  referenceUrl?: string
}

export interface ReportThreat {
  id: number
  threatName: string
  threatDescription: string
  strideCategory: string | null
  taxonomyEntries?: ReportThreatTaxonomyEntry[]
  inherentSeverity: string
  residualSeverity: string
  status: string
  countermeasures: ReportCountermeasure[]
}

export interface ReportTriagedThreat {
  id: number
  type: 'component' | 'dataflow'
  threatName: string
  componentName?: string
  flowLabel?: string
  triageStatus: string
  decisionRationale: string
}

export interface ReportThreatAnalysis {
  strideSummary: Record<string, number>
  componentThreats: Record<string, ReportThreat[]>
  dataFlowThreats: Record<string, ReportThreat[]>
  triagedThreats: ReportTriagedThreat[]
}

export interface ReportGap {
  id: number
  countermeasureName: string
  componentName?: string
  flowLabel?: string
  priority: string
  assignedOwnerEmail: string | null
}

export interface ReportCountermeasureSummary {
  statusBreakdown: Record<string, number>
  gaps: ReportGap[]
  waived: Array<{
    id: number
    countermeasureName: string
    componentName?: string
    flowLabel?: string
  }>
  inherited: Array<{
    id: number
    countermeasureName: string
    componentName: string
    inheritedFromComponentName: string
    inheritedFromZoneName: string
  }>
}

export interface ReportRisk {
  id: number
  name: string
  description: string
  inherentScore: number
  inherentLevel: string
  residualScore: number
  residualLevel: string
  ownerEmail: string | null
  contributingThreats: Array<{
    type: 'component' | 'dataflow'
    threatName: string
    status: string
  }>
}

export interface ReportComplianceFramework {
  name: string
  slug: string
  totalRequirements: number
  coveredRequirements: number
  coveragePercentage: number
  satisfiedRequirements: number
  satisfactionPercentage: number
}

export interface ReportCrossFrameworkMappingEntry {
  fromSectionCode: string
  fromDescription: string
  toSectionCode: string
  toDescription: string
  sufficiency: 'full' | 'partial'
}

export interface ReportCrossFrameworkMappingGroup {
  sourceFramework: string
  targetFramework: string
  mappings: ReportCrossFrameworkMappingEntry[]
}

export interface ReportCompliance {
  frameworks: ReportComplianceFramework[]
  crossFrameworkMappings?: ReportCrossFrameworkMappingGroup[]
}

export interface ReportSummaryMetrics {
  totalActiveThreats: number
  totalTriagedThreats: number
  threatsByStatus: Record<string, number>
  totalCountermeasures: number
  countermeasuresByStatus: Record<string, number>
  totalGaps: number
  totalWaived: number
  totalInherited: number
  totalRisks: number
  risksByLevel: Record<string, number>
}

export interface ReportProgressItem {
  id: string
  label: string
  checked: boolean
  autoComputed: boolean
}

export interface ReportSystemDefinitionItem {
  id: string
  label: string
  checked: boolean
  count: number
  countLabel: string
}

export interface ReportCoverageItem {
  id: string
  label: string
  numerator: number
  denominator: number
  percentage: number
}

export interface ReportQualitySignalFlaggedItem {
  id: number
  name: string
  detail?: string
}

export interface ReportQualitySignal {
  id: string
  status: 'ok' | 'warning'
  okLabel: string
  warningLabel: string
  flaggedItems: ReportQualitySignalFlaggedItem[]
}

export interface ReportCompletionStatus {
  systemDefinition: ReportSystemDefinitionItem[]
  coverage: ReportCoverageItem[]
  qualitySignals: ReportQualitySignal[]
}

export interface ReportData {
  metadata: ReportMetadata
  scope: ReportScope
  architecture: ReportArchitecture
  dataAssets: ReportDataAsset[]
  components: ReportComponents
  dataFlows: ReportDataFlow[]
  threatAnalysis: ReportThreatAnalysis
  countermeasureSummary: ReportCountermeasureSummary
  risks: ReportRisk[]
  compliance: ReportCompliance
  summaryMetrics: ReportSummaryMetrics
  progressChecklist: ReportProgressItem[]
  completionStatus?: ReportCompletionStatus
}
