export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type RiskResponse = 'accept' | 'mitigate' | 'transfer' | 'avoid'
export type ScoringMethodKey = 'tm_library' | 'fair' | 'owasp_rr' | 'mozilla_rra' | 'custom'

export interface Risk {
  id: number
  name: string
  description: string
  scoringMethod: ScoringMethodKey
  scoringMetadata: Record<string, unknown>
  inherentScore: number
  inherentLevel: RiskLevel
  residualScore: number | null
  residualLevel: RiskLevel | null
  response: RiskResponse | null
  threatCount: number
  threats?: RiskThreatEntry[]
  owner: number | null
  ownerEmail: string | null
  assignedTo: number | null
  assignedToEmail: string | null
  formatMetadata: Record<string, unknown>
  createdAt: string
  updatedAt: string
}

export interface RiskThreatEntry {
  riskThreatId: number
  threatId: number
  threatType: 'component' | 'flow'
  threatName: string
  status: string
  triageStatus: string
}

export interface ScoringFieldSchema {
  type: 'enum' | 'number' | 'range' | 'object' | 'text'
  values?: string[]
  min?: number
  max?: number
  required: boolean
}

export interface ScoringMethod {
  key: ScoringMethodKey
  label: string
  description: string
  metadataSchema: Record<string, ScoringFieldSchema>
  available: boolean
}

export interface CreateRiskInput {
  name: string
  description?: string
  scoringMetadata: Record<string, unknown>
  inherentScore?: number
  response?: RiskResponse | null
  owner?: number | null
  assignedTo?: number | null
  componentThreatIds?: number[]
  flowThreatIds?: number[]
}

export interface UpdateRiskInput {
  name?: string
  description?: string
  scoringMetadata?: Record<string, unknown>
  inherentScore?: number
  response?: RiskResponse | null
  owner?: number | null
  assignedTo?: number | null
}

export interface AddRemoveThreatsInput {
  componentThreatIds?: number[]
  flowThreatIds?: number[]
}

export interface BulkUpdateRisksInput {
  riskIds: number[]
  response?: RiskResponse | null
  owner?: number | null
}

export interface CountermeasureComment {
  id: number
  author: number | null
  authorEmail: string | null
  componentCountermeasure: number | null
  flowCountermeasure: number | null
  body: string
  changeSummary: string
  createdAt: string
  updatedAt: string
}
