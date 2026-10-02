import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { ThreatModel, DashboardStats, System, CreateThreatModelInput, CreateSystemInput } from '@/types'
import { api, getAccessToken } from '@/lib/api'

// Query Hooks
export function useDashboardStats() {
  return useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: () => api.get<DashboardStats>('/dashboard/stats/'),
  })
}

export function useThreatModels(teamId?: number) {
  return useQuery({
    queryKey: ['threat-models', { teamId }],
    queryFn: async () => {
      const url = teamId
        ? `/threat-models/?owning_team=${teamId}`
        : '/threat-models/'
      const response = await api.get<{ results: ThreatModel[] } | ThreatModel[]>(url)
      // Handle both paginated and non-paginated responses
      return Array.isArray(response) ? response : response.results
    },
  })
}

export function useThreatModel(id: string) {
  return useQuery({
    queryKey: ['threat-models', id],
    queryFn: () => api.get<ThreatModel>(`/threat-models/${id}/`),
    enabled: !!id,
  })
}

export function useSystems() {
  return useQuery({
    queryKey: ['systems'],
    queryFn: async () => {
      const response = await api.get<{ results: System[] } | System[]>('/systems/')
      return Array.isArray(response) ? response : response.results
    },
  })
}

export function useCreateSystem() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (input: CreateSystemInput) =>
      api.post<System>('/systems/', input),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['systems'] })
    },
  })
}

// Mutation Hooks
export function useCreateThreatModel() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (input: CreateThreatModelInput) =>
      api.post<ThreatModel>('/threat-models/', input),
    onSuccess: () => {
      // Invalidate related queries to refetch data
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard', 'stats'] })
    },
  })
}

export function useUpdateThreatModel() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ThreatModel> }) =>
      api.patch<ThreatModel>(`/threat-models/${id}/`, data),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models', id] })
    },
  })
}

export function useDeleteThreatModel() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => api.delete(`/threat-models/${id}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard', 'stats'] })
      queryClient.invalidateQueries({ queryKey: ['diagrams'] })
    },
  })
}

export interface DeletePreviewDFD {
  id: string
  name: string
  nodeCount: number
}

export interface DeletePreviewResponse {
  threatModel: { id: string; name: string }
  dfdsToDelete: DeletePreviewDFD[]
  totalDfds: number
  componentsToDelete: number
  dataflowsToDelete: number
  threatsToDelete: number
  countermeasuresToDelete: number
}

export function useDeletePreview(id: string | null) {
  return useQuery({
    queryKey: ['threat-model-delete-preview', id],
    queryFn: () => api.get<DeletePreviewResponse>(`/threat-models/${id}/delete_preview/`),
    enabled: !!id,
  })
}

// DFD Delete Preview and Delete Hooks

export interface DFDDeletePreviewOrphanedComponent {
  id: number
  name: string
  libraryName: string | null
}

export interface DFDDeletePreviewResponse {
  dfd: {
    id: string
    name: string
    nodeCount: number
    componentCount: number
  }
  affectedThreatModels: Array<{ id: string; name: string }>
  orphanedComponents: DFDDeletePreviewOrphanedComponent[]
  orphanedComponentCount: number
}

export function useDFDDeletePreview(dfdId: string | null) {
  return useQuery({
    queryKey: ['dfd-delete-preview', dfdId],
    queryFn: () => api.get<DFDDeletePreviewResponse>(`/diagrams/${dfdId}/delete_preview/`),
    enabled: !!dfdId,
  })
}

export interface DeleteDFDOptions {
  dfdId: string
  deleteOrphanedComponents?: boolean
}

export function useDeleteDFD() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ dfdId, deleteOrphanedComponents = false }: DeleteDFDOptions) => {
      const params = deleteOrphanedComponents ? '?delete_orphaned_components=true' : ''
      return api.delete<{ status: string; orphanedComponentsDeleted: number }>(
        `/diagrams/${dfdId}/${params}`
      )
    },
    onSuccess: () => {
      // Invalidate all related queries
      queryClient.invalidateQueries({ queryKey: ['diagrams'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard', 'stats'] })
      // Invalidate components and threats (orphaned component deletion changes these)
      queryClient.invalidateQueries({ queryKey: ['components'] })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

// Hook to get linked systems for a threat model
export function useThreatModelSystems(threatModelId: string | undefined) {
  const { data: threatModel } = useThreatModel(threatModelId || '')
  const { data: allSystems = [] } = useSystems()

  // Filter systems to only those linked to this threat model (use String() for type-safe comparison)
  const linkedSystems = threatModel?.systemIds
    ? allSystems.filter((system) => threatModel.systemIds?.includes(String(system.id)))
    : []

  return {
    systems: linkedSystems,
    hasLinkedSystems: linkedSystems.length > 0,
  }
}

// Hook to update a component's system assignment
export function useUpdateComponentSystem() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ componentId, orgsystemId }: { componentId: number; orgsystemId: number | null }) =>
      api.patch<{ status: string }>(`/components/${componentId}/assign_system/`, {
        orgsystemId,
      }),
    onSuccess: () => {
      // Invalidate component-related queries
      queryClient.invalidateQueries({ queryKey: ['components'] })
      queryClient.invalidateQueries({ queryKey: ['diagrams'] })
    },
  })
}

// System/Model wiring mutations
export function useAddThreatModelSystem() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ threatModelId, systemId }: { threatModelId: string; systemId: number }) =>
      api.post(`/threat-models/${threatModelId}/add_system/`, { systemId }),
    onSuccess: (_, { threatModelId }) => {
      queryClient.invalidateQueries({ queryKey: ['threat-models', threatModelId] })
    },
  })
}

export function useRemoveThreatModelSystem() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ threatModelId, systemId }: { threatModelId: string; systemId: number }) =>
      api.post(`/threat-models/${threatModelId}/remove_system/`, { systemId }),
    onSuccess: (_, { threatModelId }) => {
      queryClient.invalidateQueries({ queryKey: ['threat-models', threatModelId] })
    },
  })
}

export function useAddReferencedModel() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ threatModelId, targetModelId }: { threatModelId: string; targetModelId: number }) =>
      api.post(`/threat-models/${threatModelId}/add_referenced_model/`, { targetModelId }),
    onSuccess: (_, { threatModelId }) => {
      queryClient.invalidateQueries({ queryKey: ['threat-models', threatModelId] })
    },
  })
}

export function useRemoveThreatModelPack() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ threatModelId, packId }: { threatModelId: string; packId: number }) =>
      api.post<{ status: string; dependencyWarnings: Array<{ pack: string; message: string }> }>(
        `/threat-models/${threatModelId}/remove_pack/`,
        { packId }
      ),
    onSuccess: (_, { threatModelId }) => {
      queryClient.invalidateQueries({ queryKey: ['threat-models', threatModelId] })
      queryClient.invalidateQueries({ queryKey: ['component-library'] })
      queryClient.invalidateQueries({ queryKey: ['component-library-raw'] })
      queryClient.invalidateQueries({ queryKey: ['dfd-templates'] })
      queryClient.invalidateQueries({ queryKey: ['threat-library'] })
      queryClient.invalidateQueries({ queryKey: ['countermeasure-library'] })
    },
  })
}

export function useAddThreatModelPack() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ threatModelId, packId }: { threatModelId: string; packId: number }) =>
      api.post(`/threat-models/${threatModelId}/add_pack/`, { packId }),
    onSuccess: (_, { threatModelId }) => {
      queryClient.invalidateQueries({ queryKey: ['threat-models', threatModelId] })
      queryClient.invalidateQueries({ queryKey: ['component-library'] })
      queryClient.invalidateQueries({ queryKey: ['component-library-raw'] })
      queryClient.invalidateQueries({ queryKey: ['dfd-templates'] })
      queryClient.invalidateQueries({ queryKey: ['threat-library'] })
      queryClient.invalidateQueries({ queryKey: ['countermeasure-library'] })
    },
  })
}

export function useRemoveReferencedModel() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ threatModelId, targetModelId }: { threatModelId: string; targetModelId: number }) =>
      api.post(`/threat-models/${threatModelId}/remove_referenced_model/`, { targetModelId }),
    onSuccess: (_, { threatModelId }) => {
      queryClient.invalidateQueries({ queryKey: ['threat-models', threatModelId] })
    },
  })
}

// TM-Library Import/Export

export interface ImportTmLibraryResponse {
  threatModel: { id: string; name: string }
  summary: {
    trustZones: number
    trustBoundaries: number
    actors: number
    components: number
    dataStores: number
    dataAssets: number
    dataFlows: number
    threats: number
    controls: number
    risks: number
    warnings: string[]
  }
}

export function useImportTmLibrary() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (file: File) =>
      api.uploadFile<ImportTmLibraryResponse>(
        '/threat-models/import/tm-library/',
        file,
        undefined,
        'file'
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard', 'stats'] })
    },
  })
}

export async function exportTmLibrary(threatModelId: string): Promise<void> {
  const token = getAccessToken()
  const response = await fetch(`/api/threat-models/${threatModelId}/export/tm-library/`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })

  if (!response.ok) {
    throw new Error(`Export failed: ${response.status}`)
  }

  const blob = await response.blob()
  const contentDisposition = response.headers.get('Content-Disposition')
  const filenameMatch = contentDisposition?.match(/filename="(.+)"/)
  const filename = filenameMatch?.[1] || 'threat-model-export.json'

  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}

// CycloneDX 2.0 TM-BOM Import/Export

export function useImportCycloneDx() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (file: File) =>
      api.uploadFile<ImportTmLibraryResponse>(
        '/threat-models/import/cyclonedx/',
        file,
        undefined,
        'file'
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard', 'stats'] })
    },
  })
}

export async function exportCycloneDx(threatModelId: string): Promise<void> {
  const token = getAccessToken()
  const response = await fetch(`/api/threat-models/${threatModelId}/export/cyclonedx/`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })

  if (!response.ok) {
    throw new Error(`Export failed: ${response.status}`)
  }

  const blob = await response.blob()
  const contentDisposition = response.headers.get('Content-Disposition')
  const filenameMatch = contentDisposition?.match(/filename="(.+)"/)
  const filename = filenameMatch?.[1] || 'threat-model-cyclonedx.cdx.json'

  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}
