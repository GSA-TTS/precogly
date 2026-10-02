import { Fragment, useState, useMemo, useCallback, useRef } from 'react'
import { toast } from 'sonner'
import { Cog, User, ChevronDown, ChevronUp, ChevronRight, Plus, ArrowRight, Shield, Lock, GripVertical, Loader2, Trash2, Pencil } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from '@/components/ui/resizable'
import { cn } from '@/lib/utils'
import type { DiagramNode, DataFlowEdge, CanvasData, TrustZoneNodeData } from '../../types'
import { getZoneColorConfig } from '../../types'
import type {
  ComponentThreat,
  ComponentThreatCountermeasure,
  CountermeasureStatus,
  ThreatStatus,
  ComplianceStandardMapping,
} from '../../types/threat-analysis'
import {
  deriveThreatStatus,
  COUNTERMEASURE_STATUS_CONFIG,
  THREAT_STATUS_CONFIG,
} from '../../types/threat-analysis'
import { TaxonomyBadges } from '@/components/shared/TaxonomyBadges'
import { CONTROL_FUNCTIONS, CONTROL_NATURES } from '@/types/controls'
import { EditComplianceMappingsDialog } from './EditComplianceMappingsDialog'
import { EditTaxonomyMappingsDialog } from './EditTaxonomyMappingsDialog'
import {
  parseCountermeasureId,
  useDeleteCountermeasure,
  useUnlinkCountermeasure,
  useDeleteComponent,
  useDeleteThreat,
  useUpdateThreat,
  useUpdateFlowThreat,
  useThreatPersonas,
} from '@/features/threat-models/api/threats'
import {
  buildComponentTree,
  buildNodesMap,
  getAncestryPath,
  getDirectProcessChildren,
} from './hierarchy-utils'
import { PRIORITY_CONFIG } from './severity-utils'
import { SeverityAssessmentPanel, type SeverityAssessmentData } from './SeverityAssessmentPanel'
import { ActorImpactPanel, type ActorImpactData } from './ActorImpactPanel'
import { UserSearchCombobox } from './UserSearchCombobox'
import { WaiverReasonInput } from './WaiverReasonInput'
import { ComplianceDetailSection } from './ComplianceDetailSection'
import { CountermeasureStatusButtons } from './CountermeasureStatusButtons'
import { ComponentTreeItem } from './ComponentTreeItem'
import { useTechnologies } from '../../api/component-library'
import { isActiveThreat, TRIAGE_STATUSES, TRIAGE_STATUS_COLORS, type TriageStatus } from '@/types/triage'
import { DataFlowAssetsDisplay } from './DataFlowAssetsDisplay'
import { SortableList } from '@/components/shared/SortableList'

/** Assignee type for the combobox — individuals only */
export type Assignee = { type: 'member'; userId: number; email: string; name: string | null }

// Icon map for node types
interface ComponentViewProps {
  threatModelId: string
  canvasData: CanvasData
  analyzableComponents: DiagramNode[]
  trustZones: DiagramNode[]
  dataFlows: DataFlowEdge[]
  componentThreats: ComponentThreat[]

  selectedComponentId: string | null
  selectedThreatId: string | null
  selectedComponentThreat: ComponentThreat | null
  onSelectComponent: (componentId: string) => void
  onSelectThreat: (threatId: string) => void
  onCountermeasureStatusChange: (
    componentThreatId: string,
    countermeasureId: string,
    status: CountermeasureStatus,
    notes?: string
  ) => void
  onAssignOwner: (
    componentThreatId: string,
    countermeasureInstanceId: string,
    assignee: Assignee,
    newStatus?: CountermeasureStatus // Optional: also update status in the same API call
  ) => void
  onAddComponent: () => void
  onAddCustomThreat: () => void
  onUpdateTriageStatus: (componentThreatId: string, triageStatus: TriageStatus, decisionRationale?: string) => void
  onAddCustomCountermeasure: () => void
  onCountermeasurePriorityChange: (
    componentThreatId: string,
    countermeasureInstanceId: string,
    priority: ComponentThreatCountermeasure['priority']
  ) => void
  onCountermeasureDueDateChange: (
    componentThreatId: string,
    countermeasureInstanceId: string,
    dueDate: string | null
  ) => void
  onCountermeasureExternalTicketChange: (
    componentThreatId: string,
    countermeasureInstanceId: string,
    externalTicketUrl: string
  ) => void
  onRevertCountermeasure?: (componentThreatId: string, countermeasureInstanceId: string) => void
  onReorderThreats?: (componentId: string, reorderedThreats: ComponentThreat[]) => void
  onReorderCountermeasures?: (componentThreatId: string, reorderedCountermeasures: ComponentThreatCountermeasure[]) => void
  isSecurityTeam?: boolean
}

/**
 * Get threat summary for a component
 */
function getComponentThreatSummary(
  componentId: string,
  threats: ComponentThreat[]
): { total: number; exposed: number; addressable: number; mitigated: number } {
  const componentThreats = threats.filter(
    (t) => t.componentId === componentId && isActiveThreat(t.triageStatus)
  )

  let exposed = 0
  let addressable = 0
  let mitigated = 0

  componentThreats.forEach((threat) => {
    const status = deriveThreatStatus(threat.countermeasures)
    if (status === 'exposed') exposed++
    else if (status === 'addressable') addressable++
    else mitigated++
  })

  return { total: componentThreats.length, exposed, addressable, mitigated }
}

/**
 * Status badge component
 */
function ThreatStatusBadge({ status }: { status: ThreatStatus }) {
  const config = THREAT_STATUS_CONFIG[status]
  return (
    <Badge variant="outline" className={cn('text-xs', config.bgColor)}>
      {config.label}
    </Badge>
  )
}

export function ComponentView({
  threatModelId,
  canvasData,
  analyzableComponents,
  trustZones,
  dataFlows,
  componentThreats,
  selectedComponentId,
  selectedThreatId,
  selectedComponentThreat,
  onSelectComponent,
  onSelectThreat,
  onCountermeasureStatusChange,
  onAssignOwner,
  onAddComponent,
  onAddCustomThreat,
  onUpdateTriageStatus,
  onAddCustomCountermeasure,
  onCountermeasurePriorityChange,
  onCountermeasureDueDateChange,
  onCountermeasureExternalTicketChange,
  onRevertCountermeasure,
  onReorderThreats,
  onReorderCountermeasures,
  isSecurityTeam,
}: ComponentViewProps) {
  const [showTriagedThreats, setShowTriagedThreats] = useState(false)
  // Track pending decision rationale for triage status changes
  const [pendingTriageFor, setPendingTriageFor] = useState<{ threatId: string; status: TriageStatus } | null>(null)
  const [triageRationale, setTriageRationale] = useState('')
  // Track which countermeasure is being assigned an owner (by countermeasure instance id)
  const [assigningOwnerFor, setAssigningOwnerFor] = useState<string | null>(null)
  // Track if we should set status to "planned" after owner assignment
  const [pendingPlannedStatus, setPendingPlannedStatus] = useState<string | null>(null)
  // Track which countermeasure is being waived (needs reason input)
  const [waivingReasonFor, setWaivingReasonFor] = useState<string | null>(null)
  // Track which countermeasures have expanded compliance sections
  const [expandedComplianceFor, setExpandedComplianceFor] = useState<Set<string>>(new Set())
  // Track collapsed nodes in the hierarchy tree
  const [collapsedNodes, setCollapsedNodes] = useState<Set<string>>(new Set())
  // Track which countermeasure is having its compliance mappings edited
  const [editingComplianceFor, setEditingComplianceFor] = useState<{
    id: string
    backendId: number
    name: string
    mappings: ComplianceStandardMapping[]
  } | null>(null)
  // Track which threat is having its taxonomy entries edited
  const [editingTaxonomyFor, setEditingTaxonomyFor] = useState<{
    backendId: number
    threatType: 'component' | 'flow'
    name: string
    libraryEntries: import('@/types/domain').TaxonomyEntry[]
  } | null>(null)
  // Track which countermeasure is being deleted/unlinked
  const [deleteCountermeasureConfirmFor, setDeleteCountermeasureConfirmFor] = useState<{
    id: string
    name: string
    backendId: number
    type: 'component' | 'dataflow'
    isShared?: boolean
    threatId?: number
  } | null>(null)
  // Track which component is being deleted
  const [deleteComponentConfirmFor, setDeleteComponentConfirmFor] = useState<{
    id: number
    name: string
  } | null>(null)
  const [deleteThreatConfirmFor, setDeleteThreatConfirmFor] = useState<{
    backendId: number
    name: string
    threatType: 'component' | 'dataflow'
  } | null>(null)
  const [editingThreatFor, setEditingThreatFor] = useState<{
    backendId: number
    threatType: 'component' | 'dataflow'
    name: string
    description: string
  } | null>(null)
  const [editThreatName, setEditThreatName] = useState('')
  const [editThreatDescription, setEditThreatDescription] = useState('')

  // Resolve technology slugs to display names
  const { technologies } = useTechnologies()
  const resolveTechName = useCallback(
    (value: string | undefined) => {
      if (!value) return ''
      const match = technologies.find(
        (t) => t.id === value || t.name.toLowerCase() === value.toLowerCase()
      )
      return match?.name ?? value
    },
    [technologies]
  )

  // Threat update mutations
  const updateThreatMutation = useUpdateThreat()
  const updateFlowThreatMutation = useUpdateFlowThreat()
  const deleteCountermeasureMutation = useDeleteCountermeasure()
  const unlinkCountermeasureMutation = useUnlinkCountermeasure()
  const deleteComponentMutation = useDeleteComponent()
  const deleteThreatMutation = useDeleteThreat()

  // Refs to collect latest data from child panels
  const severityDataRef = useRef<SeverityAssessmentData | null>(null)
  const actorImpactDataRef = useRef<ActorImpactData | null>(null)

  // Unified save handler — merges severity + actor/impact data into one PATCH
  const handleSaveThreat = useCallback((threat: ComponentThreat) => {
    if (!threat.backendThreatId) return
    const data: Record<string, unknown> = {}
    if (severityDataRef.current) {
      data.severityScoringMetadata = severityDataRef.current.severityScoringMetadata
      data.inherentSeverity = severityDataRef.current.inherentSeverity
    }
    if (actorImpactDataRef.current) {
      data.impactDescription = actorImpactDataRef.current.impactDescription
      data.threatActorText = actorImpactDataRef.current.threatActorText
    }
    const onSuccess = () => { toast.success('Threat saved') }
    const onError = () => { toast.error('Failed to save threat') }
    if (threat.threatType === 'dataflow') {
      updateFlowThreatMutation.mutate({ threatId: threat.backendThreatId, data }, { onSuccess, onError })
    } else {
      updateThreatMutation.mutate({ threatId: threat.backendThreatId, data }, { onSuccess, onError })
    }
  }, [updateThreatMutation, updateFlowThreatMutation])

  const handleSaveEditThreat = useCallback(() => {
    if (!editingThreatFor || !editThreatName.trim()) return
    const data: Record<string, unknown> = {
      threatName: editThreatName.trim(),
      threatDescription: editThreatDescription.trim(),
    }
    const onSuccess = () => {
      toast.success('Threat updated')
      setEditingThreatFor(null)
    }
    const onError = () => { toast.error('Failed to update threat') }
    if (editingThreatFor.threatType === 'dataflow') {
      updateFlowThreatMutation.mutate({ threatId: editingThreatFor.backendId, data }, { onSuccess, onError })
    } else {
      updateThreatMutation.mutate({ threatId: editingThreatFor.backendId, data }, { onSuccess, onError })
    }
  }, [editingThreatFor, editThreatName, editThreatDescription, updateThreatMutation, updateFlowThreatMutation])

  // Unified delete/unlink handler for countermeasures
  const handleConfirmDeleteCountermeasure = useCallback(() => {
    if (!deleteCountermeasureConfirmFor) return

    const onSuccess = () => {
      toast.success(deleteCountermeasureConfirmFor.isShared ? 'Countermeasure unlinked' : 'Countermeasure deleted')
      setDeleteCountermeasureConfirmFor(null)
    }

    const onError = () => {
      toast.error(deleteCountermeasureConfirmFor.isShared ? 'Failed to unlink countermeasure' : 'Failed to delete countermeasure')
    }

    // Use unlink which cascade-deletes if last link
    if (deleteCountermeasureConfirmFor.threatId) {
      const threatType = deleteCountermeasureConfirmFor.type === 'dataflow' ? 'dataflow' as const : 'component' as const
      unlinkCountermeasureMutation.mutate(
        { countermeasureId: deleteCountermeasureConfirmFor.backendId, threatId: deleteCountermeasureConfirmFor.threatId, threatType },
        { onSuccess, onError }
      )
    } else {
      // Fallback: direct delete (shouldn't happen in normal flow)
      deleteCountermeasureMutation.mutate(deleteCountermeasureConfirmFor.backendId, { onSuccess, onError })
    }
  }, [deleteCountermeasureConfirmFor, deleteCountermeasureMutation, unlinkCountermeasureMutation])

  // Unified delete handler for components
  const handleConfirmDeleteComponent = useCallback(() => {
    if (!deleteComponentConfirmFor) return

    const onSuccess = () => {
      toast.success('Component deleted')
      setDeleteComponentConfirmFor(null)
    }

    const onError = () => {
      toast.error('Failed to delete component')
    }

    deleteComponentMutation.mutate(deleteComponentConfirmFor.id, { onSuccess, onError })
  }, [deleteComponentConfirmFor, deleteComponentMutation])

  const handleConfirmDeleteThreat = useCallback(() => {
    if (!deleteThreatConfirmFor) return

    deleteThreatMutation.mutate(
      { threatId: deleteThreatConfirmFor.backendId, threatType: deleteThreatConfirmFor.threatType },
      {
        onSuccess: () => {
          toast.success('Threat deleted')
          setDeleteThreatConfirmFor(null)
        },
        onError: () => {
          toast.error('Failed to delete threat')
        },
      }
    )
  }, [deleteThreatConfirmFor, deleteThreatMutation])

  // Fetch threat personas for the threat model
  const { data: threatPersonas = [] } = useThreatPersonas(threatModelId)
  const personas = useMemo(() =>
    threatPersonas.map((p) => ({ id: p.id, name: p.name })),
    [threatPersonas]
  )

  const toggleComplianceExpanded = (cmId: string) => {
    setExpandedComplianceFor(prev => {
      const next = new Set(prev)
      if (next.has(cmId)) {
        next.delete(cmId)
      } else {
        next.add(cmId)
      }
      return next
    })
  }

  // Build nodes map for hierarchy lookups
  const nodesMap = useMemo(
    () => buildNodesMap(canvasData.nodes),
    [canvasData.nodes]
  )

  // Build component tree for the left panel
  const { treeRoots } = useMemo(
    () => buildComponentTree(analyzableComponents, canvasData.nodes),
    [analyzableComponents, canvasData.nodes]
  )

  const toggleNodeCollapsed = useCallback((nodeId: string) => {
    setCollapsedNodes((prev) => {
      const next = new Set(prev)
      if (next.has(nodeId)) {
        next.delete(nodeId)
      } else {
        next.add(nodeId)
      }
      return next
    })
  }, [])

  // Get selected component or data flow
  const selectedComponent = useMemo(() => {
    if (!selectedComponentId) return null
    return canvasData.nodes.find((n) => n.id === selectedComponentId) || null
  }, [canvasData.nodes, selectedComponentId])

  const selectedDataFlow = useMemo(() => {
    if (!selectedComponentId) return null
    return dataFlows.find((e) => e.id === selectedComponentId) || null
  }, [dataFlows, selectedComponentId])

  const selectedTrustZone = useMemo(() => {
    if (!selectedComponentId) return null
    return trustZones.find((n) => n.id === selectedComponentId) || null
  }, [trustZones, selectedComponentId])

  // Ancestry path for breadcrumb (only for process nodes with ancestors)
  const ancestryPath = useMemo(() => {
    if (!selectedComponent || selectedComponent.type !== 'process') return []
    const path = getAncestryPath(selectedComponent.id, nodesMap)
    return path.length > 1 ? path : []
  }, [selectedComponent, nodesMap])

  // Direct process children of the selected component
  const childProcesses = useMemo(() => {
    if (!selectedComponent || selectedComponent.type !== 'process') return []
    return getDirectProcessChildren(selectedComponent.id, canvasData.nodes)
  }, [selectedComponent, canvasData.nodes])

  // Helper to get source and target node labels for a data flow
  const getDataFlowLabels = (edge: DataFlowEdge) => {
    const sourceNode = canvasData.nodes.find((n) => n.id === edge.source)
    const targetNode = canvasData.nodes.find((n) => n.id === edge.target)
    const sourceLabel = sourceNode ? String(sourceNode.data.label) : edge.source
    const targetLabel = targetNode ? String(targetNode.data.label) : edge.target
    return { sourceLabel, targetLabel }
  }

  // Get threats for selected component
  const threatsForComponent = useMemo(() => {
    if (!selectedComponentId) return []
    return componentThreats.filter((ct) => ct.componentId === selectedComponentId)
  }, [componentThreats, selectedComponentId])

  const activeThreats = useMemo(
    () => threatsForComponent.filter((t) => isActiveThreat(t.triageStatus)).sort((a, b) => (a.displayOrder ?? 0) - (b.displayOrder ?? 0)),
    [threatsForComponent]
  )
  const triagedThreats = threatsForComponent.filter((t) => !isActiveThreat(t.triageStatus))

  // Selected threat already contains metadata from backend
  const selectedThreatDef = selectedComponentThreat

  // Handle owner assignment from UserSearchCombobox
  const handleAssignOwner = (countermeasureInstanceId: string, assignee: Assignee) => {
    if (selectedComponentThreat) {
      const statusToSet = pendingPlannedStatus ? 'planned' as CountermeasureStatus : undefined
      onAssignOwner(selectedComponentThreat.id, countermeasureInstanceId, assignee, statusToSet)

      if (pendingPlannedStatus) {
        setPendingPlannedStatus(null)
      }

      setAssigningOwnerFor(null)
    }
  }

  // Cancel owner assignment
  const handleCancelAssignment = () => {
    setAssigningOwnerFor(null)
    setPendingPlannedStatus(null)
  }

  // Handle waiver reason submission
  const handleWaiverSubmit = (countermeasureId: string, reason: string) => {
    if (selectedComponentThreat) {
      onCountermeasureStatusChange(selectedComponentThreat.id, countermeasureId, 'waived', reason)
      setWaivingReasonFor(null)
    }
  }

  // Cancel waiver reason input
  const handleCancelWaiver = () => {
    setWaivingReasonFor(null)
  }

  // Sort countermeasures by displayOrder
  const sortedCountermeasures = useMemo(
    () => [...(selectedComponentThreat?.countermeasures || [])].sort(
      (a, b) => (a.displayOrder ?? 0) - (b.displayOrder ?? 0)
    ),
    [selectedComponentThreat?.countermeasures]
  )

  // Total countermeasures count
  const totalCountermeasures = selectedComponentThreat?.countermeasures.length || 0
  const resolvedCountermeasures = selectedComponentThreat?.countermeasures.filter(
    (cm) => cm.status !== 'gap'
  ).length || 0

  return (
    <div className="min-h-0 flex-1 overflow-hidden h-full">
      <ResizablePanelGroup orientation="horizontal">
      {/* Column 1: Components */}
      <ResizablePanel defaultSize="20%" minSize="12%" maxSize="35%">
      <div className="h-full flex flex-col">
        {/* Components list header */}
        <div className="px-3 py-2 border-b">
          <div className="flex items-center justify-between">
            <div className="font-medium">Components & Zones</div>
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs gap-1"
              onClick={onAddComponent}
            >
              <Plus className="h-3 w-3" />
              Add
            </Button>
          </div>
          <div className="text-xs text-muted-foreground">
            {analyzableComponents.length} components &nbsp;|&nbsp;{' '}
            {trustZones.length} zones &nbsp;|&nbsp;{' '}
            {dataFlows.length} flows &nbsp;|&nbsp;{' '}
            {componentThreats.filter((t) => isActiveThreat(t.triageStatus)).length} threats
          </div>
          {(() => {
            const summary = componentThreats.reduce(
              (acc, t) => {
                if (!isActiveThreat(t.triageStatus)) return acc
                const status = deriveThreatStatus(t.countermeasures)
                if (status === 'exposed') acc.exposed++
                else if (status === 'addressable') acc.addressable++
                return acc
              },
              { exposed: 0, addressable: 0 }
            )
            if (summary.exposed > 0) {
              return (
                <Badge variant="outline" className="mt-1 bg-red-100 text-red-700 text-xs">
                  {summary.exposed} exposed
                </Badge>
              )
            }
            if (summary.addressable > 0) {
              return (
                <Badge variant="outline" className="mt-1 bg-yellow-100 text-yellow-700 text-xs">
                  {summary.addressable} in progress
                </Badge>
              )
            }
            return null
          })()}
        </div>

        {/* Components list */}
        <ScrollArea className="flex-1">
          <div className="p-2 space-y-1">
            {/* Process nodes as a tree */}
            {treeRoots.map((treeNode) => (
              <ComponentTreeItem
                key={treeNode.node.id}
                treeNode={treeNode}
                componentThreats={componentThreats}
                selectedComponentId={selectedComponentId}
                collapsedNodes={collapsedNodes}
                onSelectComponent={onSelectComponent}
                onToggleCollapsed={toggleNodeCollapsed}
                resolveTechName={resolveTechName}
                onRequestDeleteComponent={(component) => setDeleteComponentConfirmFor(component)}
              />
            ))}

            {/* Trust Boundaries section */}
            {trustZones.length > 0 && (
              <>
                <div className="pt-3 pb-1 px-2 border-t mt-2">
                  <span className="text-xs font-medium text-muted-foreground">Trust Zones</span>
                </div>
                {trustZones.map((node) => {
                  const summary = getComponentThreatSummary(node.id, componentThreats)
                  const isSelected = node.id === selectedComponentId
                  const zoneData = node.data as TrustZoneNodeData
                  const zoneConfig = getZoneColorConfig(zoneData.zoneColor)

                  return (
                    <button
                      key={node.id}
                      onClick={() => onSelectComponent(node.id)}
                      className={cn(
                        'w-full text-left p-2 rounded-md transition-colors',
                        isSelected
                          ? 'bg-slate-100 border border-slate-300'
                          : 'hover:bg-slate-50'
                      )}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 min-w-0">
                          <Shield
                            className="h-4 w-4 flex-shrink-0"
                            style={{ color: zoneConfig.borderColor }}
                          />
                          <div className="min-w-0">
                            <div className="font-medium text-sm truncate">
                              {String(node.data.label)}
                            </div>
                            <div className="text-xs text-muted-foreground truncate">
                              TL: {zoneData.trustLevel ?? 75}
                            </div>
                          </div>
                        </div>
                        {summary.exposed > 0 ? (
                          <Badge variant="outline" className="bg-red-100 text-red-700 text-xs ml-2 flex-shrink-0">
                            {summary.exposed} exposed
                          </Badge>
                        ) : summary.addressable > 0 ? (
                          <Badge variant="outline" className="bg-yellow-100 text-yellow-700 text-xs ml-2 flex-shrink-0">
                            {summary.addressable} in progress
                          </Badge>
                        ) : summary.total > 0 ? (
                          <span className="text-xs text-muted-foreground ml-2 flex-shrink-0">
                            No threats
                          </span>
                        ) : null}
                      </div>
                      {summary.total > 0 && (
                        <div className="flex items-center gap-1 mt-1 ml-6">
                          <span
                            className={cn(
                              'w-2 h-2 rounded-full',
                              summary.exposed > 0 ? 'bg-red-500' : 'bg-yellow-500'
                            )}
                          />
                          <span className="text-xs text-muted-foreground">
                            {summary.total}
                          </span>
                        </div>
                      )}
                    </button>
                  )
                })}
              </>
            )}

            {/* Data Flows section */}
            {dataFlows.length > 0 && (
              <>
                <div className="pt-3 pb-1 px-2 border-t mt-2">
                  <span className="text-xs font-medium text-muted-foreground">Data Flows</span>
                </div>
                {dataFlows.map((edge) => {
                  const summary = getComponentThreatSummary(edge.id, componentThreats)
                  const isSelected = edge.id === selectedComponentId
                  const { sourceLabel, targetLabel } = getDataFlowLabels(edge)
                  const flowLabel = edge.data?.label || `${sourceLabel} → ${targetLabel}`
                  const dataflowId = edge.data?.dataflowId as number | undefined

                  return (
                    <Fragment key={edge.id}>
                      <button
                        onClick={() => onSelectComponent(edge.id)}
                        className={cn(
                          'w-full text-left p-2 rounded-md transition-colors',
                          isSelected
                            ? 'bg-slate-100 border border-slate-300'
                            : 'hover:bg-slate-50'
                        )}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 min-w-0">
                            <ArrowRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                            <div className="min-w-0">
                              <div className="font-medium text-sm truncate">
                                {flowLabel}
                              </div>
                              <div className="text-xs text-muted-foreground truncate">
                                {sourceLabel} → {targetLabel}
                              </div>
                            </div>
                          </div>
                          {summary.exposed > 0 ? (
                            <Badge variant="outline" className="bg-red-100 text-red-700 text-xs ml-2 flex-shrink-0">
                              {summary.exposed} exposed
                            </Badge>
                          ) : summary.addressable > 0 ? (
                            <Badge variant="outline" className="bg-yellow-100 text-yellow-700 text-xs ml-2 flex-shrink-0">
                              {summary.addressable} in progress
                            </Badge>
                          ) : summary.total > 0 ? (
                            <span className="text-xs text-muted-foreground ml-2 flex-shrink-0">
                              No threats
                            </span>
                          ) : null}
                        </div>
                        {summary.total > 0 && (
                          <div className="flex items-center gap-1 mt-1 ml-6">
                            <span
                              className={cn(
                                'w-2 h-2 rounded-full',
                                summary.exposed > 0 ? 'bg-red-500' : 'bg-yellow-500'
                              )}
                            />
                            <span className="text-xs text-muted-foreground">
                              {summary.total}
                            </span>
                          </div>
                        )}
                      </button>
                      {isSelected && (
                        <DataFlowAssetsDisplay dataFlowId={dataflowId} />
                      )}
                    </Fragment>
                  )
                })}
              </>
            )}
          </div>
        </ScrollArea>
      </div>
      </ResizablePanel>

      <ResizableHandle withHandle />

      {/* Column 2: Threats */}
      <ResizablePanel defaultSize="35%" minSize="20%" maxSize="55%">
      <div className="h-full flex flex-col">
        <div className="px-3 py-2 border-b">
          <div className="flex items-center justify-between">
            <div className="font-medium">Threats</div>
            <div className="flex items-center gap-2">
              {activeThreats.length > 0 && (
                <Badge variant="outline" className="text-xs">
                  {activeThreats.length} active
                </Badge>
              )}
              {selectedComponentId && (
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 text-xs gap-1"
                  onClick={onAddCustomThreat}
                >
                  <Plus className="h-3 w-3" />
                  Add
                </Button>
              )}
            </div>
          </div>
          {/* Breadcrumb path for nested process nodes */}
          {ancestryPath.length > 1 && (
            <div className="flex items-center gap-1 text-[11px] text-muted-foreground mb-0.5 flex-wrap">
              {ancestryPath.map((ancestor, index) => {
                const isLast = index === ancestryPath.length - 1
                const ancestorNodeLabel = String(ancestor.data.label)
                const ancestorTechName = resolveTechName((ancestor.data as { technology?: string }).technology)
                const ancestorLabel = ancestorNodeLabel.toLowerCase().includes('new ')
                  ? (ancestorTechName || ancestorNodeLabel)
                  : ancestorNodeLabel
                return (
                  <span key={ancestor.id} className="flex items-center gap-1">
                    {index > 0 && <ChevronRight className="h-3 w-3 flex-shrink-0" />}
                    {isLast ? (
                      <span className="font-semibold text-foreground">{ancestorLabel}</span>
                    ) : (
                      <button
                        className="hover:text-foreground hover:underline"
                        onClick={() => onSelectComponent(ancestor.id)}
                      >
                        {ancestorLabel}
                      </button>
                    )}
                  </span>
                )
              })}
            </div>
          )}
          <div className="text-xs text-muted-foreground">
            {selectedComponent
              ? resolveTechName((selectedComponent.data as { technology?: string }).technology) || String(selectedComponent.data.label)
              : selectedTrustZone
                ? String(selectedTrustZone.data.label)
                : selectedDataFlow
                  ? (() => {
                      const { sourceLabel, targetLabel } = getDataFlowLabels(selectedDataFlow)
                      return selectedDataFlow.data?.label || `${sourceLabel} → ${targetLabel}`
                    })()
                  : 'Select a component, boundary, or data flow'}
          </div>
        </div>

        {/* Child Components section */}
        {childProcesses.length > 0 && (
          <div className="px-3 py-2 border-b">
            <div className="flex items-center gap-1.5 text-xs">
              <Cog className="h-3 w-3 text-muted-foreground" />
              <span className="font-medium text-muted-foreground">Child Components</span>
              <Badge variant="secondary" className="h-4 px-1 text-[10px]">
                {childProcesses.length}
              </Badge>
            </div>
            <div className="mt-1.5 space-y-0.5">
              {childProcesses.map((child) => {
                const childNodeLabel = String(child.data.label)
                const childTechName = resolveTechName((child.data as { technology?: string }).technology)
                const childLabel = childNodeLabel.toLowerCase().includes('new ')
                  ? (childTechName || childNodeLabel)
                  : childNodeLabel
                const childSummary = getComponentThreatSummary(child.id, componentThreats)
                return (
                  <button
                    key={child.id}
                    className="w-full flex items-center gap-2 py-1 px-1 text-xs rounded hover:bg-slate-50"
                    onClick={() => onSelectComponent(child.id)}
                  >
                    {childSummary.exposed > 0 && (
                      <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />
                    )}
                    <span className="truncate text-blue-600 hover:underline">{childLabel}</span>
                  </button>
                )
              })}
            </div>
          </div>
        )}

        <ScrollArea className="flex-1">
          <div className="p-2 space-y-1">
            {/* Active Threats - shown with dismiss button */}
            {activeThreats.length > 0 && (
              <div>
                <p className="text-xs text-muted-foreground px-2 py-1 mb-1">
                  Triage or delete threats that are not relevant
                </p>

                <SortableList
                  items={activeThreats}
                  getItemId={(ct) => ct.id}
                  onReorder={(reordered) => {
                    if (selectedComponentId && onReorderThreats) {
                      onReorderThreats(selectedComponentId, reordered)
                    }
                  }}
                  renderItem={(ct, dragHandleRef) => {
                    if (!ct.threatName) return null

                    const status = deriveThreatStatus(ct.countermeasures)
                    const isSelected = ct.id === selectedThreatId

                    return (
                      <div
                        className={cn(
                          'group p-2 rounded-md transition-colors',
                          isSelected
                            ? 'bg-slate-100 border border-slate-300'
                            : 'hover:bg-slate-50'
                        )}
                      >
                        <div className="flex items-center gap-1">
                          <div
                            ref={dragHandleRef}
                            className="flex-shrink-0 cursor-grab opacity-0 group-hover:opacity-100 touch:opacity-100 transition-opacity"
                          >
                            <GripVertical className="h-4 w-4 text-muted-foreground" />
                          </div>
                          <div
                            role="button"
                            tabIndex={0}
                            onClick={() => onSelectThreat(ct.id)}
                            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onSelectThreat(ct.id) }}
                            className="flex-1 text-left min-w-0 overflow-hidden cursor-pointer"
                          >
                            <div className="flex items-center gap-2">
                              <span
                                className="w-2 h-2 rounded-full flex-shrink-0"
                                style={{ backgroundColor: THREAT_STATUS_CONFIG[status].color }}
                              />
                              <span className="font-medium text-sm truncate">
                                {ct.threatName}
                              </span>
                            </div>
                            {!isSelected && (
                              <div className="mt-1 ml-4">
                                <TaxonomyBadges entries={ct.taxonomyEntries} maxVisible={1} size="sm" />
                              </div>
                            )}
                          </div>
                          <ThreatStatusBadge status={status} />
                          <Select
                            value={ct.triageStatus}
                            onValueChange={(value: string) => {
                              const newStatus = value as TriageStatus
                              if (newStatus === 'accept' || newStatus === 'delegate' || newStatus === 'eliminate') {
                                setPendingTriageFor({ threatId: ct.id, status: newStatus })
                                setTriageRationale('')
                              } else {
                                onUpdateTriageStatus(ct.id, newStatus)
                              }
                            }}
                          >
                            <SelectTrigger className="h-6 w-[100px] text-xs flex-shrink-0" onClick={(e) => e.stopPropagation()}>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {TRIAGE_STATUSES.map((s) => (
                                <SelectItem key={s.value} value={s.value} className="text-xs">
                                  {s.label}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          {ct.backendThreatId && (
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-6 w-6 flex-shrink-0 opacity-0 group-hover:opacity-100 touch:opacity-100 transition-opacity text-muted-foreground hover:text-foreground"
                              onClick={(e) => {
                                e.stopPropagation()
                                setEditingThreatFor({
                                  backendId: ct.backendThreatId!,
                                  threatType: ct.threatType === 'dataflow' ? 'dataflow' : 'component',
                                  name: ct.threatName || '',
                                  description: ct.threatDescription || '',
                                })
                                setEditThreatName(ct.threatName || '')
                                setEditThreatDescription(ct.threatDescription || '')
                              }}
                              title="Edit threat"
                            >
                              <Pencil className="h-3 w-3" />
                            </Button>
                          )}
                          {ct.backendThreatId && (
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-6 w-6 flex-shrink-0 opacity-0 group-hover:opacity-100 touch:opacity-100 transition-opacity text-muted-foreground hover:text-destructive"
                              onClick={(e) => {
                                e.stopPropagation()
                                setDeleteThreatConfirmFor({
                                  backendId: ct.backendThreatId!,
                                  name: ct.threatName || 'this threat',
                                  threatType: ct.threatType || 'component',
                                })
                              }}
                              title="Delete threat"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          )}
                        </div>
                        {isSelected && (
                          <div className="mt-1 ml-4 flex items-center gap-1">
                            <TaxonomyBadges entries={ct.taxonomyEntries} size="sm" />
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-5 w-5 text-muted-foreground hover:text-foreground shrink-0"
                              onClick={(e) => {
                                e.stopPropagation()
                                setEditingTaxonomyFor({
                                  backendId: ct.backendThreatId!,
                                  threatType: ct.threatType === 'dataflow' ? 'flow' : 'component',
                                  name: ct.threatName || '',
                                  libraryEntries: (ct.taxonomyEntries || []).filter(
                                    (entry) => entry.source === 'library' || !entry.source
                                  ),
                                })
                              }}
                              title="Edit taxonomy entries"
                            >
                              <Pencil className="h-3 w-3" />
                            </Button>
                          </div>
                        )}
                        {pendingTriageFor?.threatId === ct.id && (
                          <div className="mt-2 ml-4 p-2 rounded-md bg-amber-50 border border-amber-200 space-y-2" onClick={(e) => e.stopPropagation()}>
                            <div className="text-xs font-medium text-amber-800">
                              Provide rationale for {TRIAGE_STATUSES.find((s) => s.value === pendingTriageFor.status)?.label}:
                            </div>
                            <input
                              type="text"
                              value={triageRationale}
                              onChange={(e) => setTriageRationale(e.target.value)}
                              placeholder="Why is this the right decision?"
                              className="w-full h-8 px-2 text-sm border rounded bg-background"
                              autoFocus
                              onKeyDown={(e) => {
                                if (e.key === 'Enter' && triageRationale.trim()) {
                                  onUpdateTriageStatus(ct.id, pendingTriageFor.status, triageRationale.trim())
                                  setPendingTriageFor(null)
                                  setTriageRationale('')
                                }
                              }}
                            />
                            <div className="flex items-center gap-2">
                              <Button
                                size="sm"
                                className="h-7 text-xs"
                                disabled={!triageRationale.trim()}
                                onClick={() => {
                                  onUpdateTriageStatus(ct.id, pendingTriageFor.status, triageRationale.trim())
                                  setPendingTriageFor(null)
                                  setTriageRationale('')
                                }}
                              >
                                Confirm
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-7 text-xs"
                                onClick={() => {
                                  setPendingTriageFor(null)
                                  setTriageRationale('')
                                }}
                              >
                                Cancel
                              </Button>
                            </div>
                          </div>
                        )}
                        {isSelected && (
                          <div className="mt-1 ml-4 p-2 rounded-md bg-slate-50 border border-slate-200 space-y-3" onClick={(e) => e.stopPropagation()}>
                            <SeverityAssessmentPanel
                              threat={ct}
                              onChange={(data) => { severityDataRef.current = data }}
                            />
                            <ActorImpactPanel
                              threat={ct}
                              personas={personas}
                              onChange={(data) => { actorImpactDataRef.current = data }}
                            />
                            <Button
                              size="sm"
                              className="h-7 text-xs w-full"
                              onClick={() => handleSaveThreat(ct)}
                              disabled={updateThreatMutation.isPending || updateFlowThreatMutation.isPending}
                            >
                              {(updateThreatMutation.isPending || updateFlowThreatMutation.isPending) ? (
                                <><Loader2 className="h-3 w-3 animate-spin mr-1" /> Saving...</>
                              ) : (
                                'Save'
                              )}
                            </Button>
                          </div>
                        )}
                      </div>
                    )
                  }}
                />
              </div>
            )}

            {/* Empty state */}
            {selectedComponentId && activeThreats.length === 0 && triagedThreats.length === 0 && (
              <div className="text-center py-8 text-muted-foreground">
                <p className="text-sm">No threats available for this component.</p>
              </div>
            )}

            {/* All threats triaged away state */}
            {selectedComponentId && activeThreats.length === 0 && triagedThreats.length > 0 && (
              <div className="text-center py-8 text-muted-foreground">
                <p className="text-sm">All threats have been triaged.</p>
                <p className="text-xs mt-1">Reopen from the section below if needed.</p>
              </div>
            )}

            {/* Triaged threats section */}
            {selectedComponentId && triagedThreats.length > 0 && (
              <div className="mt-4 pt-3 border-t">
                <button
                  className="w-full flex items-center justify-between px-2 py-1 text-sm text-muted-foreground hover:text-foreground"
                  onClick={() => setShowTriagedThreats(!showTriagedThreats)}
                >
                  <div className="flex items-center gap-2">
                    <span className="font-medium">Triaged Threats</span>
                    <Badge variant="outline" className="text-xs bg-slate-100">
                      {triagedThreats.length}
                    </Badge>
                  </div>
                  {showTriagedThreats ? (
                    <ChevronUp className="h-4 w-4" />
                  ) : (
                    <ChevronDown className="h-4 w-4" />
                  )}
                </button>

                {showTriagedThreats && (
                  <div className="mt-2 space-y-1">
                    {triagedThreats.map((ct) => {
                      if (!ct.threatName) return null
                      const statusLabel = TRIAGE_STATUSES.find((s) => s.value === ct.triageStatus)?.label || ct.triageStatus

                      return (
                        <div
                          key={ct.id}
                          className="group flex items-center justify-between gap-2 px-2 py-2 rounded-md hover:bg-slate-50"
                        >
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-sm text-muted-foreground line-through truncate">
                                {ct.threatName}
                              </span>
                              <Badge variant="outline" className={cn('text-[10px]', TRIAGE_STATUS_COLORS[ct.triageStatus])}>
                                {statusLabel}
                              </Badge>
                            </div>
                            {ct.decisionRationale && (
                              <p className="text-xs text-muted-foreground mt-0.5 italic truncate">
                                {ct.decisionRationale}
                              </p>
                            )}
                            <TaxonomyBadges entries={ct.taxonomyEntries} maxVisible={1} size="sm" />
                          </div>
                          <div className="flex items-center gap-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 text-xs text-blue-600 hover:text-blue-700 hover:bg-blue-50"
                              onClick={() => onUpdateTriageStatus(ct.id, 'open')}
                            >
                              Reopen
                            </Button>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            )}
          </div>
        </ScrollArea>
      </div>
      </ResizablePanel>

      <ResizableHandle withHandle />

      {/* Column 3: Countermeasures */}
      <ResizablePanel defaultSize="45%" minSize="20%">
      <div className="h-full flex flex-col">
        <div className="px-4 py-2 border-b flex items-center justify-between">
          <div>
            <div className="font-medium">Countermeasures</div>
            <div className="text-xs text-muted-foreground">
              {selectedThreatDef?.threatName || 'Select a threat'}
            </div>
          </div>
          <div className="flex items-center gap-2">
            {selectedComponentThreat && (
              <ThreatStatusBadge status={deriveThreatStatus(selectedComponentThreat.countermeasures)} />
            )}
            {selectedComponentThreat && (
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs gap-1"
                onClick={onAddCustomCountermeasure}
              >
                <Plus className="h-3 w-3" />
                Add
              </Button>
            )}
          </div>
        </div>

        {/* Legend */}
        {selectedComponentThreat && (
          <div className="px-4 py-2 border-b flex items-center gap-4 text-xs">
            <div className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-green-500" />
              <span className="text-muted-foreground">Platform</span>
              <Lock className="h-3 w-3 text-muted-foreground" />
            </div>
            <span className="text-muted-foreground/40">|</span>
            <div className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              <span className="text-muted-foreground">Gap</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-yellow-500" />
              <span className="text-muted-foreground">Planned</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-green-500" />
              <span className="text-muted-foreground">Verified</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-blue-500" />
              <span className="text-muted-foreground">Waived</span>
            </div>
          </div>
        )}

        <ScrollArea className="flex-1">
          <div className="p-4 space-y-3">
            {/* Countermeasures */}
            {selectedComponentThreat && sortedCountermeasures.length > 0 && (
              <SortableList
                items={sortedCountermeasures}
                getItemId={(cm) => cm.id}
                onReorder={(reordered) => {
                  if (selectedComponentThreat && onReorderCountermeasures) {
                    onReorderCountermeasures(selectedComponentThreat.id, reordered)
                  }
                }}
                renderItem={(cm, dragHandleRef) => {
                  const cmName = cm.countermeasureName || cm.countermeasureId
                  const cmDescription = cm.countermeasureDescription
                  const canDelete = (() => {
                    const parsed = parseCountermeasureId(cm.id)
                    return parsed.id !== null && parsed.type !== 'local'
                  })()

                  const statusConfig = COUNTERMEASURE_STATUS_CONFIG[cm.status]
                  const isAssigning = assigningOwnerFor === cm.id
                  const isWaiving = waivingReasonFor === cm.id

                  return (
                    <div className="group border rounded-lg p-3 mb-3">
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <div
                            ref={dragHandleRef}
                            className="flex-shrink-0 cursor-grab opacity-0 group-hover:opacity-100 touch:opacity-100 transition-opacity"
                          >
                            <GripVertical className="h-4 w-4 text-muted-foreground" />
                          </div>
                          <span
                            className="w-2 h-2 rounded-full flex-shrink-0"
                            style={{ backgroundColor: statusConfig.color }}
                          />
                          <div>
                            <div className="font-medium text-sm">{cmName}</div>
                            {cmDescription && (
                              <div className="text-xs text-muted-foreground mt-0.5">
                                {cmDescription}
                              </div>
                            )}
                          </div>
                        </div>
                        {canDelete && (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 opacity-0 group-hover:opacity-100 touch:opacity-100 transition-opacity text-muted-foreground hover:text-destructive"
                            onClick={(e) => {
                              e.stopPropagation()
                              const parsed = parseCountermeasureId(cm.id)
                              if (parsed.id === null || parsed.type === 'local') return
                              setDeleteCountermeasureConfirmFor({
                                id: cm.id,
                                name: cmName,
                                backendId: parsed.id,
                                type: selectedComponentThreat?.threatType || 'component',
                                isShared: cm.isShared,
                                threatId: selectedComponentThreat?.backendThreatId,
                              })
                            }}
                            aria-label={`Delete ${cmName}`}
                            title="Delete countermeasure"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        )}
                      </div>

                      {/* Control function & nature */}
                      {((cm.controlFunctions && cm.controlFunctions.length > 0) || cm.controlNature) && (
                        <div className="mt-2 flex flex-wrap items-center gap-1.5">
                          {cm.controlFunctions?.map((fn) => {
                            const label = CONTROL_FUNCTIONS.find((f) => f.value === fn)?.label || fn
                            return (
                              <Badge key={fn} variant="outline" className="text-xs capitalize">
                                {label}
                              </Badge>
                            )
                          })}
                          {cm.controlNature && (
                            <Badge variant="secondary" className="text-xs capitalize">
                              {CONTROL_NATURES.find((n) => n.value === cm.controlNature)?.label || cm.controlNature}
                            </Badge>
                          )}
                        </div>
                      )}

                      {/* Compliance mappings - expandable detail */}
                      {cm.standardMappings && cm.standardMappings.length > 0 ? (
                        <ComplianceDetailSection
                          mappings={cm.standardMappings}
                          isExpanded={expandedComplianceFor.has(cm.id)}
                          onToggle={() => toggleComplianceExpanded(cm.id)}
                          onEdit={() => {
                            const parsed = parseCountermeasureId(cm.id)
                            if (parsed.id !== null && parsed.type !== 'local') {
                              setEditingComplianceFor({
                                id: cm.id,
                                backendId: parsed.id,
                                name: cmName,
                                mappings: cm.standardMappings || [],
                              })
                            }
                          }}
                        />
                      ) : (
                        <button
                          className="mt-2 text-xs text-blue-600 hover:text-blue-700 flex items-center gap-1"
                          onClick={() => {
                            const parsed = parseCountermeasureId(cm.id)
                            if (parsed.id !== null && parsed.type !== 'local') {
                              setEditingComplianceFor({
                                id: cm.id,
                                backendId: parsed.id,
                                name: cmName,
                                mappings: [],
                              })
                            }
                          }}
                        >
                          <Shield className="h-3 w-3" />
                          <span>Add compliance mapping</span>
                        </button>
                      )}

                      {/* Priority */}
                      <div className="mt-2 flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">Priority:</span>
                        <Select
                          value={cm.priority || 'none'}
                          onValueChange={(value) => {
                            onCountermeasurePriorityChange(
                              selectedComponentThreat.id,
                              cm.id,
                              value as ComponentThreatCountermeasure['priority']
                            )
                          }}
                        >
                          <SelectTrigger className="h-7 w-28 text-xs">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {Object.entries(PRIORITY_CONFIG).map(([key, config]) => (
                              <SelectItem key={key} value={key}>
                                <Badge variant="outline" className={cn('text-[10px]', config.color)}>
                                  {config.label}
                                </Badge>
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>

                      {/* Owner display */}
                      {cm.owner && !isAssigning && (
                        <div className="mt-2 text-xs text-blue-600 flex items-center gap-1">
                          <User className="h-3 w-3" />
                          <span>{cm.owner}</span>
                        </div>
                      )}

                      {/* Due date and external ticket URL */}
                      <div className="mt-2 flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">Due:</span>
                        <input
                          type="date"
                          value={cm.dueDate || ''}
                          onChange={(e) => {
                            const newDueDate = e.target.value ? e.target.value : null
                            onCountermeasureDueDateChange(
                              selectedComponentThreat.id,
                              cm.id,
                              newDueDate
                            )
                          }}
                          className={cn(
                            'h-7 px-2 text-xs border rounded bg-background w-auto',
                            cm.dueDate && cm.dueDate < new Date().toISOString().split('T')[0]
                              ? 'border-red-500 text-red-600 bg-red-50'
                              : ''
                          )}
                        />
                      </div>
                      <div className="mt-2 flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">Ticket:</span>
                        <input
                          type="url"
                          placeholder="https://..."
                          value={cm.externalTicketUrl || ''}
                          onChange={(e) => {
                            onCountermeasureExternalTicketChange(
                              selectedComponentThreat.id,
                              cm.id,
                              e.target.value
                            )
                          }}
                          className="h-7 px-2 text-xs border rounded bg-background w-full min-w-0"
                        />
                      </div>

                      {/* Provided by boundary badge */}
                      {cm.providedByBoundaryId && (
                        <div className="mt-2 text-xs text-green-600 flex items-center gap-1 bg-green-50 px-2 py-1 rounded border border-green-200">
                          <Shield className="h-3 w-3" />
                          <span>
                            Provided by{' '}
                            <span className="font-medium">
                              {(() => {
                                const boundary = canvasData.nodes.find((n) => n.id === cm.providedByBoundaryId)
                                if (!boundary) return 'boundary'
                                const zoneData = boundary.data as TrustZoneNodeData
                                return String(zoneData.label || 'boundary')
                              })()}
                            </span>
                          </span>
                        </div>
                      )}

                      {/* Inherited from zone badge */}
                      {cm.isInherited && cm.inheritedFromZoneName && (
                        <div className="mt-2 text-xs text-purple-600 flex items-center gap-1 bg-purple-50 px-2 py-1 rounded border border-purple-200">
                          <Shield className="h-3 w-3" />
                          <span className="flex-1">
                            Inherited from{' '}
                            <span className="font-medium">
                              {cm.inheritedFromComponentName}
                            </span>
                            {' '}({cm.inheritedFromZoneName})
                          </span>
                          {onRevertCountermeasure && selectedComponentThreat && (
                            <button
                              className="text-purple-500 hover:text-purple-700 underline ml-2"
                              onClick={() => onRevertCountermeasure(selectedComponentThreat.id, cm.id)}
                            >
                              Revert
                            </button>
                          )}
                        </div>
                      )}

                      {/* Also mitigates indicator for shared countermeasures */}
                      {cm.alsoMitigates && cm.alsoMitigates.length > 0 && (
                        <div className="mt-2 text-xs text-muted-foreground bg-blue-50/50 px-2 py-1.5 rounded border border-blue-100">
                          <span className="font-medium text-blue-600">Also mitigates:</span>
                          {cm.alsoMitigates.map((target) => (
                            <div key={target.threatId} className="ml-3 text-muted-foreground">
                              {target.componentName
                                ? <>{target.componentName} &rsaquo; {target.threatName}</>
                                : target.threatName}
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Waiver reason display */}
                      {cm.status === 'waived' && cm.notes && !isWaiving && (
                        <div className="mt-2 text-xs text-muted-foreground bg-blue-50 p-2 rounded border border-blue-200">
                          <span className="font-medium text-blue-700">Waiver reason:</span>{' '}
                          {cm.notes}
                        </div>
                      )}

                      {/* Owner assignment UI */}
                      {isAssigning ? (
                        <div className="mt-3">
                          <div className="text-xs font-medium text-muted-foreground mb-2">
                            {pendingPlannedStatus === cm.countermeasureId
                              ? 'Assign an owner to mark as Planned:'
                              : 'Assign owner:'}
                          </div>
                          <UserSearchCombobox
                            value={cm.owner || ''}
                            onSelect={(user) => handleAssignOwner(cm.id, user)}
                            onCancel={handleCancelAssignment}
                          />
                        </div>
                      ) : isWaiving ? (
                        <div className="mt-3">
                          <WaiverReasonInput
                            onSubmit={(reason) => handleWaiverSubmit(cm.id, reason)}
                            onCancel={handleCancelWaiver}
                          />
                        </div>
                      ) : (
                        <div className="mt-2 flex items-center justify-between">
                          <CountermeasureStatusButtons
                            status={cm.status}
                            isPlatformLevel={cm.status === 'platform'}
                            isSecurityTeam={isSecurityTeam}
                            hasOwner={!!cm.owner}
                            onChange={(status) =>
                              onCountermeasureStatusChange(
                                selectedComponentThreat.id,
                                cm.id,
                                status
                              )
                            }
                            onPlannedWithoutOwner={() => {
                              setAssigningOwnerFor(cm.id)
                              setPendingPlannedStatus(cm.countermeasureId)
                            }}
                            onWaivedWithoutReason={() => {
                              setWaivingReasonFor(cm.id)
                            }}
                          />
                          {!cm.owner && cm.status !== 'platform' && (
                            <Button
                              variant="link"
                              size="sm"
                              className="h-auto p-0 text-xs"
                              onClick={() => setAssigningOwnerFor(cm.id)}
                            >
                              Assign owner
                            </Button>
                          )}
                        </div>
                      )}
                    </div>
                  )
                }}
              />
            )}


          </div>
        </ScrollArea>

        {/* Footer */}
        {selectedComponentThreat && (
          <div className="px-4 py-2 border-t text-xs text-muted-foreground flex justify-between">
            <span>{totalCountermeasures} countermeasures</span>
            <span>{resolvedCountermeasures} resolved</span>
          </div>
        )}
      </div>
      </ResizablePanel>
      </ResizablePanelGroup>

      {/* Edit Compliance Mappings Dialog */}
      {editingComplianceFor && (
        <EditComplianceMappingsDialog
          open={!!editingComplianceFor}
          onOpenChange={(open) => {
            if (!open) setEditingComplianceFor(null)
          }}
          countermeasureId={editingComplianceFor.backendId}
          countermeasureName={editingComplianceFor.name}
          libraryMappings={editingComplianceFor.mappings}
        />
      )}

      {/* Edit Taxonomy Mappings Dialog */}
      {editingTaxonomyFor && (
        <EditTaxonomyMappingsDialog
          open={!!editingTaxonomyFor}
          onOpenChange={(open) => {
            if (!open) setEditingTaxonomyFor(null)
          }}
          threatId={editingTaxonomyFor.backendId}
          threatType={editingTaxonomyFor.threatType}
          threatName={editingTaxonomyFor.name}
          libraryTaxonomyEntries={editingTaxonomyFor.libraryEntries}
        />
      )}

      <AlertDialog
        open={!!deleteCountermeasureConfirmFor}
        onOpenChange={(open) => {
          if (!open) setDeleteCountermeasureConfirmFor(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {deleteCountermeasureConfirmFor?.isShared ? 'Remove countermeasure from this threat?' : 'Delete countermeasure?'}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {deleteCountermeasureConfirmFor?.isShared
                ? `This will remove "${deleteCountermeasureConfirmFor?.name || 'this countermeasure'}" from this threat. It will remain active for the other threats it mitigates.`
                : `This will permanently delete ${deleteCountermeasureConfirmFor?.name || 'this countermeasure'}. This action cannot be undone.`
              }
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteCountermeasureMutation.isPending || unlinkCountermeasureMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault()
                handleConfirmDeleteCountermeasure()
              }}
              disabled={deleteCountermeasureMutation.isPending || unlinkCountermeasureMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteCountermeasureMutation.isPending || unlinkCountermeasureMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Deleting...
                </>
              ) : (
                'Delete'
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={!!deleteComponentConfirmFor}
        onOpenChange={(open) => {
          if (!open) setDeleteComponentConfirmFor(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete component?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete {deleteComponentConfirmFor?.name || 'this component'} and all of its associated threats and countermeasures.
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteComponentMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault()
                handleConfirmDeleteComponent()
              }}
              disabled={deleteComponentMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteComponentMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Deleting...
                </>
              ) : (
                'Delete'
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={!!deleteThreatConfirmFor}
        onOpenChange={(open) => {
          if (!open) setDeleteThreatConfirmFor(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete threat?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete "{deleteThreatConfirmFor?.name}" and all of its countermeasures.
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteThreatMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault()
                handleConfirmDeleteThreat()
              }}
              disabled={deleteThreatMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteThreatMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Deleting...
                </>
              ) : (
                'Delete'
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Edit Threat Dialog */}
      <Dialog
        open={!!editingThreatFor}
        onOpenChange={(open) => {
          if (!open) setEditingThreatFor(null)
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Threat</DialogTitle>
            <DialogDescription>Update the threat name and description.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="edit-threat-name">Threat Name *</Label>
              <Input
                id="edit-threat-name"
                value={editThreatName}
                onChange={(e) => setEditThreatName(e.target.value)}
                placeholder="Threat name"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-threat-description">Description</Label>
              <Textarea
                id="edit-threat-description"
                value={editThreatDescription}
                onChange={(e) => setEditThreatDescription(e.target.value)}
                placeholder="Describe the threat..."
                rows={4}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingThreatFor(null)}>
              Cancel
            </Button>
            <Button
              onClick={handleSaveEditThreat}
              disabled={!editThreatName.trim() || updateThreatMutation.isPending || updateFlowThreatMutation.isPending}
            >
              {(updateThreatMutation.isPending || updateFlowThreatMutation.isPending) ? (
                <><Loader2 className="h-3 w-3 animate-spin mr-1" /> Saving...</>
              ) : (
                'Save'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
