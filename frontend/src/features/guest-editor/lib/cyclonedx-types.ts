/**
 * TypeScript interfaces for CycloneDX 2.0 TM-BOM document structure.
 * Matches the backend adapter's export format for guest-editor serialization.
 */

export interface CycloneDxDocument {
  specFormat: 'CycloneDX'
  specVersion: string
  serialNumber: string
  version: number
  metadata: CycloneDxMetadata
  blueprints: CycloneDxBlueprint[]
  controls?: CycloneDxControl[]
  threats?: CycloneDxThreatsBlock
  risks?: CycloneDxRisksBlock
}

export interface CycloneDxMetadata {
  timestamp: string
  tools?: {
    components?: { type: string; name: string; version: string }[]
  }
  authors?: { name?: string; email?: string }[]
}

export interface CycloneDxBlueprint {
  'bom-ref'?: string
  name: string
  description?: string
  modelTypes?: string[]
  zones?: CycloneDxZone[]
  assets?: CycloneDxAsset[]
  flows?: CycloneDxFlow[]
  boundaries?: CycloneDxBoundary[]
  dataSets?: CycloneDxDataSet[]
  assumptions?: CycloneDxAssumption[]
  visualizations?: CycloneDxVisualization[]
}

export interface CycloneDxZone {
  'bom-ref': string
  name: string
  type?: string
  description?: string
  trustLevel?: number
  parent?: string
}

export interface CycloneDxAsset {
  'bom-ref': string
  name: string
  type: string
  description?: string
  zone?: string
}

export interface CycloneDxFlow {
  'bom-ref': string
  name?: string
  description?: string
  source: string
  destination: string
  type?: string
  protocols?: string[]
  encrypted?: boolean
  authenticated?: boolean
}

export interface CycloneDxBoundary {
  'bom-ref'?: string
  name?: string
  description?: string
  zones: string[]
  crossingRequirements?: Record<string, unknown>
}

export interface CycloneDxDataSet {
  'bom-ref': string
  name: string
  description?: string
  classification?: string
}

export interface CycloneDxAssumption {
  'bom-ref': string
  description: string
  validity?: string
  topic?: string
}

export interface CycloneDxVisualization {
  type: string
  name?: string
  diagramType?: string
  data?: Record<string, unknown>
}

export interface CycloneDxControl {
  'bom-ref': string
  name: string
  description?: string
  status?: string
  category?: string
  effectiveness?: { percentage?: number }
  mitigations?: string[]
  properties?: CycloneDxProperty[]
}

export interface CycloneDxThreatsBlock {
  threats?: CycloneDxThreat[]
  scenarios?: CycloneDxScenario[]
  methodologies?: { type: string }[]
}

export interface CycloneDxProperty {
  name: string
  value: string
}

export interface CycloneDxThreat {
  'bom-ref': string
  name: string
  description?: string
  categories?: CycloneDxThreatCategory[]
  affectedAssets?: string[]
  mitigations?: string[]
  properties?: CycloneDxProperty[]
}

export interface CycloneDxThreatCategory {
  taxonomy?: string
  id?: string
  name?: string
}

export interface CycloneDxScenario {
  'bom-ref': string
  threat: string
  affectedAssets?: string[]
  riskScore?: CycloneDxRiskScore
  properties?: CycloneDxProperty[]
}

export interface CycloneDxRiskScore {
  level?: string
  score?: number
}

export interface CycloneDxRisksBlock {
  risks?: CycloneDxRisk[]
}

export interface CycloneDxRisk {
  'bom-ref': string
  name: string
  statement?: string
  inherentRisk?: { riskScore: CycloneDxRiskScore }
  residualRisk?: { riskScore: CycloneDxRiskScore }
  relatedThreats?: string[]
  responses?: CycloneDxRiskResponse[]
}

export interface CycloneDxRiskResponse {
  strategy?: string
  description?: string
  status?: string
}
