import { useState, useEffect, useCallback, useMemo } from 'react'
import type { Diagram } from '@/types'
import type {
  CompletionStatus,
  ComponentThreat,
  ComponentThreatCountermeasure,
  CountermeasureStatus,
  ProgressChecklistItem,
} from '@/features/dfd-editor/types/threat-analysis'
import { deriveThreatStatus } from '@/features/dfd-editor/types/threat-analysis'
import {
  useThreatModelThreats,
  useUpdateCountermeasure,
  useUpdateTriageStatus,
  useUpdateFlowTriageStatus,
  parseCountermeasureId,
  parseThreatId,
  useReorderComponentThreats,
  useReorderFlowThreats,
  useReorderCountermeasures,
} from '@/features/threat-models/api/threats'
import { isActiveThreat, type TriageStatus } from '@/types/triage'
import { useThreatModel } from '@/features/threat-models/api/threat-models'

interface WorkspaceThreatAnalysisState {
  threatModelId: string
  componentThreats: ComponentThreat[]
}

function getDefaultState(threatModelId: string | undefined): WorkspaceThreatAnalysisState {
  return {
    threatModelId: threatModelId || '',
    componentThreats: [],
  }
}

// NOTE: Local threat generation has been removed from this hook.
// The backend is now the single source of truth for threats.

export function useWorkspaceThreatAnalysis(
  threatModelId: string | undefined,
  diagrams: Diagram[],
  analysisComponents: { id: number; category: string }[] = []
) {
  const [state, setState] = useState<WorkspaceThreatAnalysisState>(() =>
    getDefaultState(threatModelId)
  )

  // Fetch threat model for workspace_data
  const { data: threatModel, isLoading: isLoadingThreatModel } = useThreatModel(threatModelId!)

  // Fetch threats from backend API
  const { data: backendThreats, isLoading: isLoadingThreats } = useThreatModelThreats(threatModelId)

  // Backend API mutations
  const updateCountermeasureMutation = useUpdateCountermeasure()
  const updateTriageStatusMutation = useUpdateTriageStatus()
  const updateFlowTriageStatusMutation = useUpdateFlowTriageStatus()
  const reorderComponentThreatsMutation = useReorderComponentThreats()
  const reorderFlowThreatsMutation = useReorderFlowThreats()
  const reorderCountermeasuresMutation = useReorderCountermeasures()

  // Use backend threats directly - no local threat generation
  useEffect(() => {
    if (backendThreats?.componentThreats) {
      setState((prev) => ({
        ...prev,
        componentThreats: backendThreats.componentThreats,
      }))
    }
  }, [backendThreats])

  // Filter threats when diagrams change (remove threats for deleted diagrams/components)
  useEffect(() => {
    if (!diagrams || diagrams.length === 0) return
    if (isLoadingThreats) return

    setState((prev) => {
      const validComponentIds = new Set<string>()
      const currentDiagramIds = new Set<string>()
      diagrams.forEach((d) => {
        currentDiagramIds.add(String(d.id))
        const canvasData = d.canvasData
        if (canvasData) {
          canvasData.nodes?.forEach((node) => validComponentIds.add(String(node.id)))
          canvasData.edges?.forEach((edge) => validComponentIds.add(String(edge.id)))
        }
      })

      const filteredThreats = prev.componentThreats.filter((ct) => {
        const isAnalysisOnly = String(ct.componentId).startsWith('analysis-') ||
                               (!ct.sourceDiagramId && !ct.diagramId)
        if (isAnalysisOnly) return true

        const diagramId = String(ct.sourceDiagramId || ct.diagramId)
        if (!currentDiagramIds.has(diagramId)) return false
        if (!validComponentIds.has(String(ct.componentId))) return false
        return true
      })

      if (filteredThreats.length !== prev.componentThreats.length) {
        return { ...prev, componentThreats: filteredThreats }
      }
      return prev
    })
  }, [diagrams, isLoadingThreats])

  // Revert an inherited countermeasure back to gap status
  const revertInheritedCountermeasure = useCallback(
    (componentThreatId: string, countermeasureInstanceId: string) => {
      const parsed = parseCountermeasureId(countermeasureInstanceId)
      if (parsed.type === 'backend' && parsed.id !== null) {
        updateCountermeasureMutation.mutate({
          countermeasureId: parsed.id,
          data: {
            status: 'gap',
            isInherited: false,
            inheritedFromComponentName: '',
            inheritedFromZoneName: '',
          },
        })
      }
      // Optimistic local state update
      setState((prev) => ({
        ...prev,
        componentThreats: prev.componentThreats.map((ct) => {
          if (ct.id !== componentThreatId) return ct
          return {
            ...ct,
            countermeasures: ct.countermeasures.map((cm) => {
              if (cm.id !== countermeasureInstanceId) return cm
              return {
                ...cm,
                status: 'gap' as CountermeasureStatus,
                isInherited: false,
                inheritedFromComponentName: undefined,
                inheritedFromZoneName: undefined,
              }
            }),
          }
        }),
      }))
    },
    [updateCountermeasureMutation]
  )

  // Update countermeasure status
  const updateCountermeasureStatus = useCallback(
    (
      _componentThreatId: string,
      countermeasureInstanceId: string,
      status: CountermeasureStatus,
      notes?: string
    ) => {
      // Use the instance ID directly for the API call (always unique)
      const parsed = parseCountermeasureId(countermeasureInstanceId)

      if (parsed.type === 'backend' && parsed.id !== null) {
        updateCountermeasureMutation.mutate({
          countermeasureId: parsed.id,
          data: {
            status: status as 'platform' | 'gap' | 'planned' | 'verified' | 'waived',
            ...(notes !== undefined && { evidenceUrl: notes }),
          },
        })
      }

      // Update local state immediately for responsiveness
      // For shared countermeasures, update across ALL threats that share this CM
      setState((prev) => ({
        ...prev,
        componentThreats: prev.componentThreats.map((ct) => {
          const hasCm = ct.countermeasures.some((cm) => cm.id === countermeasureInstanceId)
          if (!hasCm) return ct
          return {
            ...ct,
            updatedAt: new Date().toISOString(),
            countermeasures: ct.countermeasures.map((cm) => {
              if (cm.id !== countermeasureInstanceId) return cm
              return {
                ...cm,
                status,
                ...(notes !== undefined && { notes }),
                updatedAt: new Date().toISOString(),
              }
            }),
          }
        }),
      }))
    },
    [updateCountermeasureMutation]
  )

  // Assign owner to countermeasure
  const assignOwner = useCallback(
    (
      componentThreatId: string,
      countermeasureInstanceId: string,
      assignee: { type: 'member'; userId: number; email: string; name: string | null },
      newStatus?: CountermeasureStatus
    ) => {
      const threat = state.componentThreats.find((ct) => ct.id === componentThreatId)
      const countermeasure = threat?.countermeasures.find((cm) => cm.id === countermeasureInstanceId)

      if (countermeasure) {
        const parsed = parseCountermeasureId(countermeasure.id)

        const data: { assignedOwner: number; status?: CountermeasureStatus } = { assignedOwner: assignee.userId }
        if (newStatus) {
          data.status = newStatus
        }

        if (parsed.type === 'backend' && parsed.id !== null) {
          updateCountermeasureMutation.mutate({
            countermeasureId: parsed.id,
            data,
          })
        }
      }

      const finalStatus = newStatus || (countermeasure?.status === 'gap' ? 'planned' : countermeasure?.status)
      setState((prev) => ({
        ...prev,
        componentThreats: prev.componentThreats.map((ct) => {
          if (ct.id !== componentThreatId) return ct
          return {
            ...ct,
            updatedAt: new Date().toISOString(),
            countermeasures: ct.countermeasures.map((cm) => {
              if (cm.id !== countermeasureInstanceId) return cm
              return {
                ...cm,
                owner: assignee.email,
                status: finalStatus || cm.status,
                updatedAt: new Date().toISOString(),
              }
            }),
          }
        }),
      }))
    },
    [state.componentThreats, updateCountermeasureMutation]
  )

  // Update countermeasure priority
  const updateCountermeasurePriority = useCallback(
    (componentThreatId: string, countermeasureInstanceId: string, priority: ComponentThreatCountermeasure['priority']) => {
      const threat = state.componentThreats.find((ct) => ct.id === componentThreatId)
      const countermeasure = threat?.countermeasures.find((cm) => cm.id === countermeasureInstanceId)

      if (countermeasure) {
        const parsed = parseCountermeasureId(countermeasure.id)

        if (parsed.type === 'backend' && parsed.id !== null) {
          updateCountermeasureMutation.mutate({
            countermeasureId: parsed.id,
            data: { priority },
          })
        }
      }

      // Update local state immediately for responsiveness
      setState((prev) => ({
        ...prev,
        componentThreats: prev.componentThreats.map((ct) => {
          if (ct.id !== componentThreatId) return ct
          return {
            ...ct,
            updatedAt: new Date().toISOString(),
            countermeasures: ct.countermeasures.map((cm) => {
              if (cm.id !== countermeasureInstanceId) return cm
              return {
                ...cm,
                priority,
                updatedAt: new Date().toISOString(),
              }
            }),
          }
        }),
      }))
    },
    [state.componentThreats, updateCountermeasureMutation]
  )

  // Update countermeasure due date
  const updateCountermeasureDueDate = useCallback(
    (componentThreatId: string, countermeasureInstanceId: string, dueDate: string | null) => {
      const threat = state.componentThreats.find((ct) => ct.id === componentThreatId)
      const countermeasure = threat?.countermeasures.find((cm) => cm.id === countermeasureInstanceId)

      if (countermeasure) {
        const parsed = parseCountermeasureId(countermeasure.id)

        if (parsed.type === 'backend' && parsed.id !== null) {
          updateCountermeasureMutation.mutate({
            countermeasureId: parsed.id,
            data: { dueDate },
          })
        }
      }

      setState((prev) => ({
        ...prev,
        componentThreats: prev.componentThreats.map((ct) => {
          if (ct.id !== componentThreatId) return ct
          return {
            ...ct,
            updatedAt: new Date().toISOString(),
            countermeasures: ct.countermeasures.map((cm) => {
              if (cm.id !== countermeasureInstanceId) return cm
              return { ...cm, dueDate, updatedAt: new Date().toISOString() }
            }),
          }
        }),
      }))
    },
    [state.componentThreats, updateCountermeasureMutation]
  )

  // Update countermeasure external ticket URL
  const updateCountermeasureExternalTicket = useCallback(
    (componentThreatId: string, countermeasureInstanceId: string, externalTicketUrl: string) => {
      const threat = state.componentThreats.find((ct) => ct.id === componentThreatId)
      const countermeasure = threat?.countermeasures.find((cm) => cm.id === countermeasureInstanceId)

      if (countermeasure) {
        const parsed = parseCountermeasureId(countermeasure.id)

        if (parsed.type === 'backend' && parsed.id !== null) {
          updateCountermeasureMutation.mutate({
            countermeasureId: parsed.id,
            data: { externalTicketUrl },
          })
        }
      }

      setState((prev) => ({
        ...prev,
        componentThreats: prev.componentThreats.map((ct) => {
          if (ct.id !== componentThreatId) return ct
          return {
            ...ct,
            updatedAt: new Date().toISOString(),
            countermeasures: ct.countermeasures.map((cm) => {
              if (cm.id !== countermeasureInstanceId) return cm
              return { ...cm, externalTicketUrl, updatedAt: new Date().toISOString() }
            }),
          }
        }),
      }))
    },
    [state.componentThreats, updateCountermeasureMutation]
  )

  // Update triage status
  const updateTriageStatus = useCallback((
    componentThreatId: string,
    componentId: string,
    triageStatus: TriageStatus,
    decisionRationale?: string
  ) => {
    // componentId is available for future use (e.g., optimistic updates per component)
    void componentId
    const threat = state.componentThreats.find((ct) => ct.id === componentThreatId)
    if (threat?.backendThreatId) {
      if (threat.threatType === 'dataflow') {
        updateFlowTriageStatusMutation.mutate({
          threatId: threat.backendThreatId,
          triageStatus,
          decisionRationale,
        })
      } else {
        updateTriageStatusMutation.mutate({
          threatId: threat.backendThreatId,
          triageStatus,
          decisionRationale,
        })
      }
    }
    setState((prev) => ({
      ...prev,
      componentThreats: prev.componentThreats.map((ct) => {
        if (ct.id !== componentThreatId) return ct
        return {
          ...ct,
          triageStatus,
          decisionRationale: decisionRationale ?? ct.decisionRationale,
          updatedAt: new Date().toISOString(),
        }
      }),
    }))
  }, [state.componentThreats, updateTriageStatusMutation, updateFlowTriageStatusMutation])

  // Add custom countermeasure
  const addCountermeasure = useCallback(
    (componentThreatId: string, countermeasureId: string) => {
      setState((prev) => {
        const timestamp = new Date().toISOString()
        return {
          ...prev,
          componentThreats: prev.componentThreats.map((ct) => {
            if (ct.id !== componentThreatId) return ct
            if (ct.countermeasures.some((cm) => cm.countermeasureId === countermeasureId)) {
              return ct
            }
            const newCm: ComponentThreatCountermeasure = {
              id: `ctcm-${componentThreatId}-${countermeasureId}-${Date.now()}`,
              countermeasureId,
              componentThreatId,
              status: 'gap',
              createdAt: timestamp,
              updatedAt: timestamp,
            }
            return {
              ...ct,
              updatedAt: timestamp,
              countermeasures: [...ct.countermeasures, newCm],
            }
          }),
        }
      })
    },
    []
  )

  // Reorder threats for a component
  const reorderThreats = useCallback(
    (_componentId: string, reorderedThreats: ComponentThreat[]) => {
      // Update local state immediately with new displayOrder values
      setState((prev) => {
        const reorderedIds = new Set(reorderedThreats.map((t) => t.id))
        const otherThreats = prev.componentThreats.filter((ct) => !reorderedIds.has(ct.id))
        const updatedReordered = reorderedThreats.map((t, index) => ({
          ...t,
          displayOrder: index,
        }))
        return { ...prev, componentThreats: [...otherThreats, ...updatedReordered] }
      })

      // Split IDs by type and fire mutations
      const componentThreatIds: number[] = []
      const flowThreatIds: number[] = []
      for (const threat of reorderedThreats) {
        const parsed = parseThreatId(threat.id)
        if (parsed.type === 'component' && parsed.id !== null) {
          componentThreatIds.push(parsed.id)
        } else if (parsed.type === 'flow' && parsed.id !== null) {
          flowThreatIds.push(parsed.id)
        }
      }
      if (componentThreatIds.length > 0) {
        reorderComponentThreatsMutation.mutate(componentThreatIds)
      }
      if (flowThreatIds.length > 0) {
        reorderFlowThreatsMutation.mutate(flowThreatIds)
      }
    },
    [reorderComponentThreatsMutation, reorderFlowThreatsMutation]
  )

  // Reorder countermeasures for a threat
  const reorderCountermeasures = useCallback(
    (componentThreatId: string, reorderedCountermeasures: ComponentThreatCountermeasure[]) => {
      // Update local state immediately
      setState((prev) => ({
        ...prev,
        componentThreats: prev.componentThreats.map((ct) => {
          if (ct.id !== componentThreatId) return ct
          return {
            ...ct,
            countermeasures: reorderedCountermeasures.map((cm, index) => ({
              ...cm,
              displayOrder: index,
            })),
          }
        }),
      }))

      // Collect all backend CM IDs and fire single mutation
      const backendCmIds: number[] = []
      for (const cm of reorderedCountermeasures) {
        const parsed = parseCountermeasureId(cm.id)
        if (parsed.type === 'backend' && parsed.id !== null) {
          backendCmIds.push(parsed.id)
        }
      }
      if (backendCmIds.length > 0) {
        reorderCountermeasuresMutation.mutate(backendCmIds)
      }
    },
    [reorderCountermeasuresMutation]
  )

  // Toggle checklist item — no-op since all items are now auto-computed by the backend
  const toggleChecklistItem = useCallback((_itemId: string, _checked: boolean) => {
    // All checklist items are auto-computed by the backend; no local state to update
  }, [])

  // Compute summary statistics
  const summaries = useMemo(() => {
    const activeThreats = state.componentThreats.filter((ct) => isActiveThreat(ct.triageStatus))

    const allNodes = diagrams.filter((d) => d.isPrimary).flatMap((d) => d.canvasData?.nodes || [])

    // Get IDs of components already on canvas to avoid double-counting
    const canvasComponentIds = new Set(
      allNodes
        .map((n) => n.data?.componentId)
        .filter(Boolean)
    )
    // Analysis-only components not already on canvas
    const analysisOnly = analysisComponents.filter((c) => !canvasComponentIds.has(c.id))

    const componentSummary = {
      total: allNodes.filter(
        (n) => n.type === 'process' || n.type === 'datastore' || n.type === 'humanActor' || n.type === 'systemActor'
      ).length + analysisOnly.length,
      processes: allNodes.filter((n) => n.type === 'process').length
        + analysisOnly.filter((c) => c.category === 'process').length,
      datastores: allNodes.filter((n) => n.type === 'datastore').length
        + analysisOnly.filter((c) => c.category === 'datastore').length,
      humanActors: allNodes.filter((n) => n.type === 'humanActor').length
        + analysisOnly.filter((c) => c.category === 'external_human_actor').length,
      systemActors: allNodes.filter((n) => n.type === 'systemActor').length
        + analysisOnly.filter((c) => c.category === 'external_system_actor').length,
      trustZones: allNodes.filter((n) => n.type === 'trustZone').length,
    }

    let exposedThreats = 0
    let addressableThreats = 0
    let mitigatedThreats = 0

    activeThreats.forEach((ct) => {
      const status = deriveThreatStatus(ct.countermeasures)
      if (status === 'exposed') exposedThreats++
      else if (status === 'addressable') addressableThreats++
      else mitigatedThreats++
    })

    const threatSummary = {
      total: activeThreats.length,
      exposed: exposedThreats,
      addressable: addressableThreats,
      mitigated: mitigatedThreats,
    }

    const allCountermeasures = activeThreats.flatMap((ct) => ct.countermeasures)
    const countermeasureSummary = {
      total: allCountermeasures.length,
      platform: allCountermeasures.filter((cm) => cm.status === 'platform').length,
      verified: allCountermeasures.filter((cm) => cm.status === 'verified').length,
      gap: allCountermeasures.filter((cm) => cm.status === 'gap').length,
      planned: allCountermeasures.filter((cm) => cm.status === 'planned').length,
      waived: allCountermeasures.filter((cm) => cm.status === 'waived').length,
    }

    return { componentSummary, threatSummary, countermeasureSummary }
  }, [state.componentThreats, diagrams, analysisComponents])

  // Progress checklist is computed by the backend and returned in workspace_data
  const progressChecklist: ProgressChecklistItem[] = useMemo(() => {
    const workspaceData = threatModel?.workspaceData as Record<string, unknown> | undefined
    const backendChecklist = workspaceData?.progressChecklist as ProgressChecklistItem[] | undefined
    if (backendChecklist?.length) return backendChecklist
    return []
  }, [threatModel?.workspaceData])

  // Enhanced completion status from backend
  const completionStatus: CompletionStatus | undefined = useMemo(() => {
    const workspaceData = threatModel?.workspaceData as Record<string, unknown> | undefined
    return workspaceData?.completionStatus as CompletionStatus | undefined
  }, [threatModel?.workspaceData])

  return {
    componentThreats: state.componentThreats,
    progressChecklist,
    completionStatus,
    summaries,
    isLoading: isLoadingThreats || isLoadingThreatModel,
    isLoadingThreats,
    revertInheritedCountermeasure,
    updateCountermeasureStatus,
    updateCountermeasurePriority,
    updateCountermeasureDueDate,
    updateCountermeasureExternalTicket,
    assignOwner,
    updateTriageStatus,
    addCountermeasure,
    toggleChecklistItem,
    reorderThreats,
    reorderCountermeasures,
  }
}
