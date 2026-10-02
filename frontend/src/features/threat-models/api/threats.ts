/**
 * API hooks for threat workflow endpoints.
 */

import { useQuery, useMutation, useQueryClient, skipToken } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { ComponentThreat, ComponentThreatCountermeasure, CountermeasureStatus } from '@/features/dfd-editor/types/threat-analysis'
import type { TaxonomyEntry } from '@/types/domain'
import type { TriageStatus } from '@/types/triage'
import { componentKeys } from './components'
import { riskKeys } from './risks'

// Backend countermeasure status. Aliased directly to the frontend CountermeasureStatus
// type (rather than duplicated as a literal union) so the two can no longer drift --
// this duplication is what caused precogly/precogly#328.
type BackendCountermeasureStatus = CountermeasureStatus

// Types
export interface ComponentInstanceThreat {
  id: number
  component: number
  componentName: string
  threatLibrary: number
  threatName: string
  taxonomyEntries?: TaxonomyEntry[]
  inherentSeverity: string
  residualSeverity: string
  status: 'exposed' | 'addressable' | 'mitigated'
  severityScoringMetadata: Record<string, unknown>
  triageStatus: TriageStatus
  decisionRationale: string
  formatMetadata: Record<string, unknown>
  // Actor & impact fields
  impactDescription?: string
  threatActorText?: string
  threatPersonas?: { id: number; name: string }[]
  threatSources?: { id: number; name: string; slug?: string }[]
  createdAt: string
  updatedAt: string
}

export interface CountermeasureLibraryItem {
  id: number
  name: string
  description?: string
  controlFunctions: string[]
  controlNature: string
  cost: string
  defaultStatus?: string
  sourcePackName: string | null
  sourcePackSlug: string | null
}

export interface ThreatLibraryItem {
  id: number
  name: string
  description?: string  // Optional for defensive programming
  taxonomyEntries?: TaxonomyEntry[]
  sourcePackName: string | null
  sourcePackSlug: string | null
}

export interface ComponentInstanceCountermeasure {
  id: number
  threatModel: number | string
  countermeasureLibrary: number
  countermeasureName: string
  countermeasureDescription?: string
  controlFunctions?: string[]
  controlNature?: string
  status: BackendCountermeasureStatus
  priority: string
  dueDate?: string | null
  externalTicketUrl?: string
  verifiedBy: number | null
  verifiedByEmail: string | null
  evidenceUrl: string
  requiredForRelease: boolean
  assignedOwner: number | null
  assignedOwnerEmail: string | null
  formatMetadata: Record<string, unknown>
  isInherited?: boolean
  inheritedFromComponentName?: string
  inheritedFromZoneName?: string
  threatLinks?: Array<{
    id: number
    threat: number
    threatName: string
    componentName: string | null
    displayOrder: number
  }>
  createdAt: string
  updatedAt: string
}

export interface GenerateThreatsResponse {
  createdCount: number
  existingCount: number
  total: number
  message: string
}

export interface SuggestedCountermeasuresResponse {
  threatId: number
  threatName: string
  suggested: CountermeasureLibraryItem[]
  applied: CountermeasureLibraryItem[]
  suggestedCount: number
  appliedCount: number
}

export interface ApplyCountermeasureResponse {
  countermeasure: ComponentInstanceCountermeasure
  message: string
}

export interface RecalculateStatusResponse {
  threatId: number
  oldStatus: string
  newStatus: string
  message: string
}

// Query keys
export const threatKeys = {
  all: ['threats'] as const,
  componentThreats: (componentId: number) => [...threatKeys.all, 'component', componentId] as const,
  flowThreats: (dataFlowId: number) => [...threatKeys.all, 'flow', dataFlowId] as const,
  threatCountermeasures: (threatId: number) => [...threatKeys.all, 'countermeasures', threatId] as const,
  suggestedCountermeasures: (threatId: number) => [...threatKeys.all, 'suggested', threatId] as const,
  threatLibrary: (componentId?: number | null, threatModelId?: string) =>
    componentId
      ? ['threat-library', componentId, threatModelId] as const
      : ['threat-library', threatModelId] as const,
  countermeasureLibrary: (threatModelId?: string) =>
    ['countermeasure-library', threatModelId] as const,
}

// Query Hooks

/**
 * Fetch threats for a specific component.
 */
export function useComponentThreats(componentId: number | null) {
  return useQuery({
    queryKey: threatKeys.componentThreats(componentId!),
    queryFn: async () => {
      const response = await api.get<{ results: ComponentInstanceThreat[] } | ComponentInstanceThreat[]>(
        `/component-threats/?component=${componentId}`
      )
      return Array.isArray(response) ? response : response.results
    },
    enabled: componentId !== null,
  })
}

/**
 * Threats already on a data flow.
 *
 * The component equivalent above returns the full instance; this one is only
 * ever used to answer "which library threats does this flow already have?", so
 * it stays narrow rather than duplicating the whole serializer shape.
 */
export interface FlowInstanceThreatRef {
  id: number
  threatLibrary: number | null
}

export function useFlowThreats(dataFlowId: number | null) {
  return useQuery({
    queryKey: threatKeys.flowThreats(dataFlowId!),
    queryFn: async () => {
      const response = await api.get<{ results: FlowInstanceThreatRef[] } | FlowInstanceThreatRef[]>(
        `/flow-threats/?data_flow=${dataFlowId}`
      )
      return Array.isArray(response) ? response : response.results
    },
    enabled: dataFlowId !== null,
  })
}

/**
 * Fetch suggested countermeasures for a threat instance.
 */
export function useSuggestedCountermeasures(threatId: number | null) {
  return useQuery({
    queryKey: threatKeys.suggestedCountermeasures(threatId!),
    queryFn: () => api.get<SuggestedCountermeasuresResponse>(
      `/component-threats/${threatId}/suggested_countermeasures/`
    ),
    enabled: threatId !== null,
  })
}

/**
 * Fetch threats from the threat library.
 * Optionally filter by a component's library via component_id query param.
 * Optionally filter by connected packs via threat_model query param.
 */
export function useThreatLibrary(componentId?: number | null, threatModelId?: string) {
  return useQuery({
    queryKey: threatKeys.threatLibrary(componentId, threatModelId),
    queryFn: async () => {
      const params = new URLSearchParams()
      if (componentId) params.set('component_id', String(componentId))
      if (threatModelId) params.set('threat_model', threatModelId)
      const queryString = params.toString()
      const url = queryString ? `/threat-library/?${queryString}` : '/threat-library/'
      const response = await api.get<{ results: ThreatLibraryItem[] } | ThreatLibraryItem[]>(url)
      return Array.isArray(response) ? response : response.results
    },
  })
}

/**
 * Fetch all countermeasures from the countermeasure library.
 * Optionally filter by applicable threat library ID.
 * Optionally filter by connected packs via threat_model query param.
 */
export function useCountermeasureLibrary(threatLibraryId?: number | null, threatModelId?: string) {
  return useQuery({
    queryKey: [...threatKeys.countermeasureLibrary(threatModelId), threatLibraryId],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (threatLibraryId) params.set('applicable_threats', String(threatLibraryId))
      if (threatModelId) params.set('threat_model', threatModelId)
      const queryString = params.toString()
      const url = queryString ? `/countermeasure-library/?${queryString}` : '/countermeasure-library/'
      const response = await api.get<{ results: CountermeasureLibraryItem[] } | CountermeasureLibraryItem[]>(url)
      return Array.isArray(response) ? response : response.results
    },
  })
}

// Mutation Hooks

/**
 * Generate threats for a component based on its library type.
 */
export function useGenerateThreats() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (componentId: number) =>
      api.post<GenerateThreatsResponse>(`/components/${componentId}/generate_threats/`),
    onSuccess: (_, componentId) => {
      queryClient.invalidateQueries({ queryKey: threatKeys.componentThreats(componentId) })
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
    },
  })
}

/**
 * Create a new component threat instance.
 * Can be from library (threatLibrary set) or custom (threatLibrary null).
 */
export function useCreateComponentThreat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: {
      component: number
      threatLibrary?: number | null
      threatName?: string
      threatDescription?: string
      inherentSeverity: string
      status?: string
      triageStatus?: TriageStatus
      impactDescription?: string
      threatActorText?: string
    }) => api.post<ComponentInstanceThreat>('/component-threats/', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
    },
  })
}

/**
 * Create a new flow threat instance.
 * Can be from library (threatLibrary set) or custom (threatLibrary null).
 */
export function useCreateFlowThreat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: {
      dataFlow: number
      threatLibrary?: number | null
      threatName?: string
      threatDescription?: string
      inherentSeverity: string
      status?: string
      triageStatus?: TriageStatus
      impactDescription?: string
      threatActorText?: string
    }) => api.post('/flow-threats/', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
    },
  })
}

/**
 * Create a new countermeasure instance (unified: works for both component and flow threats).
 * Can be from library (countermeasureLibrary set) or custom (countermeasureLibrary null).
 */
export function useCreateCountermeasure() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: {
      threatModel: number | string
      threatId: number
      threatType: 'component' | 'dataflow'
      countermeasureLibrary?: number | null
      countermeasureName?: string
      countermeasureDescription?: string
      controlFunctions?: string[]
      controlNature?: string
      status?: string
    }) => api.post<ComponentInstanceCountermeasure>('/countermeasures/', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: ['countermeasures-in-use'] })
      queryClient.invalidateQueries({ queryKey: riskKeys.all })
    },
  })
}

/**
 * Apply a countermeasure to a threat instance.
 * Routes to component-threats or flow-threats endpoint based on threatType.
 */
export function useApplyCountermeasure() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatId,
      threatType,
      countermeasureLibraryId,
      existingCountermeasureId,
      status,
    }: {
      threatId: number
      threatType: 'component' | 'dataflow'
      countermeasureLibraryId?: number
      existingCountermeasureId?: number
      status?: string
    }) => {
      const endpoint = threatType === 'dataflow'
        ? `/flow-threats/${threatId}/apply_countermeasure/`
        : `/component-threats/${threatId}/apply_countermeasure/`
      return api.post<ApplyCountermeasureResponse>(endpoint, {
        ...(countermeasureLibraryId && { countermeasureLibraryId }),
        ...(existingCountermeasureId && { existingCountermeasureId }),
        ...(status && { status }),
      })
    },
    onSuccess: (_, { threatId }) => {
      queryClient.invalidateQueries({ queryKey: threatKeys.suggestedCountermeasures(threatId) })
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: ['countermeasures-in-use'] })
      queryClient.invalidateQueries({ queryKey: riskKeys.all })
    },
  })
}

/**
 * Recalculate threat status based on countermeasures.
 */
export function useRecalculateThreatStatus() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (threatId: number) =>
      api.post<RecalculateStatusResponse>(`/component-threats/${threatId}/recalculate_status/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
    },
  })
}

/**
 * Update a threat instance (e.g., status, severity).
 */
export function useUpdateThreat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatId,
      data,
    }: {
      threatId: number
      data: Partial<ComponentInstanceThreat>
    }) => api.patch<ComponentInstanceThreat>(`/component-threats/${threatId}/`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
    },
  })
}

/**
 * Update a flow threat instance (e.g., status, severity).
 */
export function useUpdateFlowThreat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatId,
      data,
    }: {
      threatId: number
      data: Record<string, unknown>
    }) => api.patch(`/flow-threats/${threatId}/`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
    },
  })
}

/**
 * Update triage status for a component threat.
 */
export function useUpdateTriageStatus() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatId,
      triageStatus,
      decisionRationale,
    }: {
      threatId: number
      triageStatus: string
      decisionRationale?: string
    }) =>
      api.patch<ComponentInstanceThreat>(`/component-threats/${threatId}/`, {
        triageStatus,
        decisionRationale: decisionRationale ?? '',
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
    },
  })
}

/**
 * Update triage status for a flow threat.
 */
export function useUpdateFlowTriageStatus() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatId,
      triageStatus,
      decisionRationale,
    }: {
      threatId: number
      triageStatus: string
      decisionRationale?: string
    }) =>
      api.patch(`/flow-threats/${threatId}/`, {
        triageStatus,
        decisionRationale: decisionRationale ?? '',
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
    },
  })
}

/**
 * Update a countermeasure instance (e.g., status, evidenceUrl).
 * Unified: works for both component and flow countermeasures.
 */
export function useUpdateCountermeasure() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({
      countermeasureId,
      data,
    }: {
      countermeasureId: number
      data: Partial<ComponentInstanceCountermeasure>
    }) => {
      return api.patch<ComponentInstanceCountermeasure>(
        `/countermeasures/${countermeasureId}/`,
        data
      )
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: riskKeys.all })
    },
  })
}

/**
 * Delete a countermeasure instance.
 * Unified: works for both component and flow countermeasures.
 */
export function useDeleteCountermeasure() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (countermeasureId: number) =>
      api.delete(`/countermeasures/${countermeasureId}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: ['countermeasures-in-use'] })
      queryClient.invalidateQueries({ queryKey: riskKeys.all })
    },
  })
}

export function useDeleteThreat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ threatId, threatType }: { threatId: number; threatType: 'component' | 'dataflow' }) => {
      const endpoint = threatType === 'dataflow' ? 'flow-threats' : 'component-threats'
      return api.delete(`/${endpoint}/${threatId}/`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: riskKeys.all })
    },
  })
}

/**
 * Parse a countermeasure ID string to determine type and numeric ID.
 * Returns null if the ID format is not recognized.
 *
 * ID formats:
 * - "cm-123" -> backend countermeasure with ID 123
 * - "ctcm-..." -> local countermeasure (not backend)
 */
export function parseCountermeasureId(idString: string): {
  type: 'backend' | 'local'
  id: number | null
} {
  if (idString.startsWith('cm-')) {
    const numId = parseInt(idString.slice(3), 10)
    return { type: 'backend', id: isNaN(numId) ? null : numId }
  }
  if (idString.startsWith('ctcm-')) {
    return { type: 'local', id: null }
  }
  return { type: 'local', id: null }
}

// ============================================
// Threat Model Threats API
// ============================================

/**
 * Backend response for threat model threats endpoint.
 */
export interface EdgeDataflowMapEntry {
  dataflowId: number
  dfdId: string | null
  dfdName: string | null
  isAnalysisOnly?: boolean
  label?: string
  sourceComponentName?: string
  destComponentName?: string
}

export interface ThreatModelThreatsResponse {
  threatModelId: string
  threats: BackendThreat[]
  totalCount: number
  nodeComponentMap: Record<string, { componentId: number; dfdId: string; dfdName: string }>
  edgeDataflowMap: Record<string, EdgeDataflowMapEntry>
}

/**
 * Backend threat format.
 */
export interface BackendThreat {
  id: number
  type: 'component' | 'dataflow'
  componentId: number
  componentName: string | null
  nodeId: string | null
  edgeId?: string | null
  dataflowId?: number
  dataflowLabel?: string | null
  dfdId: string | null
  dfdName: string | null
  threatLibraryId: number
  threatName: string | null
  threatDescription: string | null
  taxonomyEntries?: TaxonomyEntry[]
  inherentSeverity: string
  residualSeverity: string
  status: 'exposed' | 'addressable' | 'mitigated'
  severityScoringMetadata: Record<string, unknown>
  triageStatus: TriageStatus
  decisionRationale: string
  displayOrder?: number
  // Actor & impact fields
  impactDescription?: string
  threatActorText?: string
  threatPersonas?: { id: number; name: string }[]
  threatSources?: { id: number; name: string; slug?: string }[]
  countermeasures: BackendCountermeasure[]
}

/**
 * Backend standard mapping format.
 */
export interface BackendStandardMapping {
  id: number
  frameworkName: string
  frameworkSlug: string
  sectionCode: string
  requirementDescription: string
  sufficiency: 'full' | 'partial'
}

/**
 * Backend countermeasure format.
 */
export interface BackendCountermeasure {
  id: number
  countermeasureLibraryId: number
  countermeasureName: string | null
  controlFunctions: string[] | null
  controlNature: string | null
  status: BackendCountermeasureStatus
  priority: string
  dueDate?: string | null
  externalTicketUrl?: string
  evidenceUrl: string
  assignedOwnerEmail: string | null
  verifiedByEmail: string | null
  standardMappings: BackendStandardMapping[]
  displayOrder?: number
  isInherited?: boolean
  inheritedFromComponentName?: string | null
  inheritedFromZoneName?: string | null
  alsoMitigates?: Array<{
    threatId: number
    threatType: 'component' | 'flow'
    threatName: string
    componentName: string | null
  }>
}

/**
 * Transform backend threats to frontend ComponentThreat format.
 */
export function transformBackendThreatsToComponentThreats(
  backendThreats: BackendThreat[]
): ComponentThreat[] {
  const now = new Date().toISOString()

  return backendThreats.map((bt) => {
    // Use different prefixes for component vs dataflow threats
    const isDataflow = bt.type === 'dataflow'
    const componentThreatId = isDataflow ? `backend-flow-${bt.id}` : `backend-${bt.id}`

    // All countermeasures use unified cm- prefix
    const countermeasures: ComponentThreatCountermeasure[] = bt.countermeasures.map((cm) => ({
      id: `cm-${cm.id}`,
      countermeasureId: `lib-${cm.countermeasureLibraryId}`,
      componentThreatId,
      status: cm.status as CountermeasureStatus,
      priority: (cm.priority || 'none') as ComponentThreatCountermeasure['priority'],
      dueDate: cm.dueDate ?? null,
      externalTicketUrl: cm.externalTicketUrl || undefined,
      owner: cm.assignedOwnerEmail || undefined,
      notes: cm.evidenceUrl || undefined,
      createdAt: now,
      updatedAt: now,
      countermeasureName: cm.countermeasureName || undefined,
      controlFunctions: cm.controlFunctions || [],
      controlNature: cm.controlNature || '',
      standardMappings: cm.standardMappings || [],
      displayOrder: cm.displayOrder ?? 0,
      isInherited: cm.isInherited || false,
      inheritedFromComponentName: cm.inheritedFromComponentName || undefined,
      inheritedFromZoneName: cm.inheritedFromZoneName || undefined,
      alsoMitigates: cm.alsoMitigates || [],
      isShared: (cm.alsoMitigates && cm.alsoMitigates.length > 0) || false,
    }))

    return {
      id: componentThreatId,
      diagramId: bt.dfdId || '',
      sourceDiagramId: bt.dfdId || undefined,
      sourceDiagramTitle: bt.dfdName || undefined,
      // For dataflows, use the edge_id as componentId (for grouping in UI)
      componentId: isDataflow
        ? (bt.edgeId || `dataflow-${bt.dataflowId}`)
        : (bt.nodeId || `component-${bt.componentId}`),
      threatId: `lib-${bt.threatLibraryId}`,
      triageStatus: bt.triageStatus || 'open',
      decisionRationale: bt.decisionRationale || '',
      countermeasures,
      createdAt: now,
      updatedAt: now,
      // Threat metadata from backend (eliminates need for frontend registry lookup)
      threatName: bt.threatName || undefined,
      threatDescription: bt.threatDescription || undefined,
      taxonomyEntries: bt.taxonomyEntries,
      // Severity scoring metadata
      inherentSeverity: bt.inherentSeverity,
      severityScoringMetadata: bt.severityScoringMetadata,
      // Display order for drag-and-drop reordering
      displayOrder: bt.displayOrder ?? 0,
      // Backend IDs for API operations
      backendThreatId: bt.id,
      backendComponentId: bt.componentId,
      threatType: bt.type,
      componentName: bt.componentName || undefined,
      dataflowLabel: bt.dataflowLabel || undefined,
      // Actor & impact fields
      impactDescription: bt.impactDescription || undefined,
      threatActorText: bt.threatActorText || undefined,
      threatPersonas: bt.threatPersonas,
      threatSources: bt.threatSources,
    }
  })
}

/**
 * Fetch all threats for a threat model (aggregated from all DFDs).
 */
export function useThreatModelThreats(threatModelId: string | null | undefined) {
  return useQuery({
    queryKey: ['threat-model-threats', threatModelId],
    queryFn: threatModelId
      ? async () => {
          const response = await api.get<ThreatModelThreatsResponse>(
            `/threat-models/${threatModelId}/threats/`
          )
          const transformed = transformBackendThreatsToComponentThreats(response.threats)
          return {
            ...response,
            componentThreats: transformed,
          }
        }
      : skipToken,
    staleTime: 30000, // Consider fresh for 30 seconds
  })
}

// ============================================
// Shared Countermeasures M2M API
// ============================================

export interface CountermeasureInUse {
  id: number
  countermeasureName: string
  countermeasureLibraryId: number | null
  status: BackendCountermeasureStatus
  assignedOwnerEmail: string | null
  linkedThreats: Array<{
    threatId: number
    threatName: string
    threatType?: 'component' | 'dataflow'
    componentName?: string | null
    flowLabel?: string | null
  }>
}

interface CountermeasuresInUseResponse {
  threatModelId: string
  countermeasures: CountermeasureInUse[]
  totalCount: number
}

/**
 * Fetch countermeasures in use for a threat model.
 */
export function useCountermeasuresInUse(threatModelId: string | null | undefined) {
  return useQuery({
    queryKey: ['countermeasures-in-use', threatModelId],
    queryFn: threatModelId
      ? async () => {
          const response = await api.get<CountermeasuresInUseResponse>(
            `/threat-models/${threatModelId}/countermeasures-in-use/`
          )
          return response
        }
      : skipToken,
    staleTime: 30000,
  })
}

/**
 * Link an existing countermeasure to an additional threat.
 * Unified: works for both component and flow threats.
 */
export function useLinkCountermeasure() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      countermeasureId,
      threatId,
      threatType,
    }: {
      countermeasureId: number
      threatId: number
      threatType: 'component' | 'dataflow'
    }) =>
      api.post(`/countermeasures/${countermeasureId}/link/`, {
        threatId,
        threatType,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['countermeasures-in-use'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: riskKeys.all })
    },
  })
}

/**
 * Unlink a countermeasure from a threat. Deletes if last link.
 * Unified: works for both component and flow threats.
 */
export function useUnlinkCountermeasure() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      countermeasureId,
      threatId,
      threatType,
    }: {
      countermeasureId: number
      threatId: number
      threatType: 'component' | 'dataflow'
    }) =>
      api.post(`/countermeasures/${countermeasureId}/unlink/`, {
        threatId,
        threatType,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['countermeasures-in-use'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: riskKeys.all })
    },
  })
}

// ============================================
// Zone Protections API
// ============================================

export interface ZoneProtectionSuggestion {
  targetCountermeasureId: number
  targetComponentName: string
  targetZoneName: string
  sourceComponentName: string
  sourceZoneName: string
  countermeasureName: string
  controlFunctions: string[]
  controlNature: string
}

interface ZoneProtectionsResponse {
  suggestions: ZoneProtectionSuggestion[]
  totalCount: number
}

interface ApplyZoneProtectionsResponse {
  updatedCount: number
}

/**
 * Fetch zone protection suggestions for a threat model.
 */
export function useZoneProtections(threatModelId: string | null | undefined, enabled = false) {
  return useQuery({
    queryKey: ['zone-protections', threatModelId],
    queryFn: threatModelId && enabled
      ? () => api.get<ZoneProtectionsResponse>(
          `/threat-models/${threatModelId}/zone_protections/`
        )
      : skipToken,
  })
}

/**
 * Parse a threat ID string to determine type and numeric ID.
 *
 * ID formats:
 * - "backend-123" -> component threat with ID 123
 * - "backend-flow-456" -> flow threat with ID 456
 */
export function parseThreatId(idString: string): {
  type: 'component' | 'flow' | 'unknown'
  id: number | null
} {
  if (idString.startsWith('backend-flow-')) {
    const numId = parseInt(idString.slice('backend-flow-'.length), 10)
    return { type: 'flow', id: isNaN(numId) ? null : numId }
  }
  if (idString.startsWith('backend-')) {
    const numId = parseInt(idString.slice('backend-'.length), 10)
    return { type: 'component', id: isNaN(numId) ? null : numId }
  }
  return { type: 'unknown', id: null }
}

/**
 * Reorder component threats.
 */
export function useReorderComponentThreats() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (orderedIds: number[]) =>
      api.post('/component-threats/reorder/', { orderedIds }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Reorder flow threats.
 */
export function useReorderFlowThreats() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (orderedIds: number[]) =>
      api.post('/flow-threats/reorder/', { orderedIds }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Reorder countermeasures.
 * Unified: works for both component and flow countermeasures.
 */
export function useReorderCountermeasures() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (orderedIds: number[]) =>
      api.post('/countermeasures/reorder/', { orderedIds }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Apply selected zone protection suggestions.
 */
export function useApplyZoneProtections() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatModelId,
      items,
    }: {
      threatModelId: string
      items: { countermeasureId: number; sourceComponentName: string; sourceZoneName: string }[]
    }) =>
      api.post<ApplyZoneProtectionsResponse>(
        `/threat-models/${threatModelId}/apply_zone_protections/`,
        { items }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['zone-protections'] })
    },
  })
}

export function useDeleteComponent() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (componentId: number) => api.delete(`/components/${componentId}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: componentKeys.all })
    },
  })
}

/**
 * Fetch threat personas for a threat model.
 */
export interface ThreatPersonaItem {
  id: number
  symbolicName: string
  name: string
  description: string
  isPerson: boolean
  maliciousIntent: boolean
}

export function useThreatPersonas(threatModelId: string | null | undefined) {
  return useQuery({
    queryKey: ['threat-personas', threatModelId],
    queryFn: threatModelId
      ? () => api.get<ThreatPersonaItem[]>(
          `/threat-models/${threatModelId}/threat-personas/`
        )
      : skipToken,
    staleTime: 5 * 60 * 1000,
  })
}

// ============================================
// Instance-Level Taxonomy Entries
// ============================================

export interface InstanceThreatTaxonomyEntry {
  id: number
  taxonomyEntry: number
  componentThreat: number | null
  flowThreat: number | null
  taxonomySlug: string
  taxonomyName: string
  externalId: string
  title: string
  referenceUrl: string
  createdAt: string
  updatedAt: string
}

const instanceTaxonomyKeys = {
  all: ['threat-taxonomy'] as const,
  byThreat: (threatId: number, threatType: 'component' | 'flow') =>
    [...instanceTaxonomyKeys.all, threatType, threatId] as const,
}

export function useInstanceTaxonomyEntries(
  threatId: number | null,
  threatType: 'component' | 'flow'
) {
  const filterParam = threatType === 'component' ? 'component_threat' : 'flow_threat'
  return useQuery({
    queryKey: instanceTaxonomyKeys.byThreat(threatId!, threatType),
    queryFn: async () => {
      const response = await api.get<
        { results: InstanceThreatTaxonomyEntry[] } | InstanceThreatTaxonomyEntry[]
      >(`/threat-taxonomy-entries/?${filterParam}=${threatId}`)
      return Array.isArray(response) ? response : response.results
    },
    enabled: threatId !== null,
  })
}

export function useCreateInstanceTaxonomyEntry() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: {
      taxonomyEntry: number
      componentThreat?: number
      flowThreat?: number
    }) =>
      api.post<InstanceThreatTaxonomyEntry>('/threat-taxonomy-entries/', {
        taxonomy_entry: data.taxonomyEntry,
        component_threat: data.componentThreat ?? null,
        flow_threat: data.flowThreat ?? null,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: instanceTaxonomyKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

export function useDeleteInstanceTaxonomyEntry() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: number) =>
      api.delete(`/threat-taxonomy-entries/${id}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: instanceTaxonomyKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}
