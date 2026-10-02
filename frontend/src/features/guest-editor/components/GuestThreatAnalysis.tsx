import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ArrowLeft,
  Cog,
  Database,
  User,
  Building2,
  ArrowRight,
  Box,
  Plus,
  Trash2,
  Pencil,
  Shield,
  AlertTriangle,
  Info,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from '@/components/ui/resizable'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useGuestEditor } from '../context/GuestEditorContext'
import { GuestThreatDialog } from './GuestAddThreatDialog'
import { GuestCountermeasureDialog } from './GuestCountermeasureDialog'
import type { GuestThreat, GuestCountermeasure } from '../types'
import { STATUS_COLORS, getThreatWarning, GUEST_THREAT_STATUS_OPTIONS } from '../types'
import { STRIDE_CONFIG } from '@/types/domain'

const SEVERITY_COLORS: Record<GuestThreat['severity'], string> = {
  low: 'bg-blue-100 text-blue-800',
  medium: 'bg-yellow-100 text-yellow-800',
  high: 'bg-orange-100 text-orange-800',
  critical: 'bg-red-100 text-red-800',
}

import type { ControlFunction, ControlNature } from '../types'

const CONTROL_FUNCTION_COLORS: Record<ControlFunction, string> = {
  preventive: 'bg-green-100 text-green-800',
  detective: 'bg-blue-100 text-blue-800',
  corrective: 'bg-orange-100 text-orange-800',
  deterrent: 'bg-purple-100 text-purple-800',
  recovery: 'bg-teal-100 text-teal-800',
  compensating: 'bg-amber-100 text-amber-800',
}

const CONTROL_NATURE_COLORS: Record<ControlNature, string> = {
  technical: 'bg-sky-100 text-sky-800',
  administrative: 'bg-rose-100 text-rose-800',
  physical: 'bg-stone-100 text-stone-800',
}

const CONTROL_NATURE_LABELS: Record<ControlNature, string> = {
  technical: 'Technical',
  administrative: 'Admin/Procedural',
  physical: 'Physical',
}

const NODE_TYPE_ICON: Record<string, typeof Cog> = {
  process: Cog,
  datastore: Database,
  humanActor: User,
  systemActor: Building2,
  systemScope: Box,
}

const NODE_TYPE_LABELS: Record<string, string> = {
  process: 'Processes',
  datastore: 'Data Stores',
  humanActor: 'Human Actors',
  systemActor: 'System Actors',
  systemScope: 'System Scope',
}

type ThreatSortField = 'status' | 'severity' | 'name'

const SORT_OPTIONS: { value: ThreatSortField; label: string }[] = [
  { value: 'status', label: 'Status' },
  { value: 'severity', label: 'Severity' },
  { value: 'name', label: 'Name' },
]

const STATUS_SORT_ORDER: Record<string, number> = {
  open: 0, mitigate: 1, accept: 2, delegate: 3, eliminate: 4,
}

const SEVERITY_SORT_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3,
}

interface ComponentItem {
  id: string
  label: string
  type: string
  targetType: GuestThreat['targetType']
}

export function GuestThreatAnalysis() {
  const navigate = useNavigate()
  const guestEditor = useGuestEditor()

  const [selectedComponentId, setSelectedComponentId] = useState<string | null>(null)
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null)
  const [sortField, setSortField] = useState<ThreatSortField>('status')

  // Threat dialog state
  const [showThreatDialog, setShowThreatDialog] = useState(false)
  const [editingThreat, setEditingThreat] = useState<GuestThreat | undefined>(undefined)

  // Countermeasure dialog state
  const [showCountermeasureDialog, setShowCountermeasureDialog] = useState(false)
  const [editingCountermeasure, setEditingCountermeasure] = useState<
    GuestCountermeasure | undefined
  >(undefined)

  if (!guestEditor) return null

  const { nodes, edges } = guestEditor

  // Build component list grouped by type
  const componentsByType = useMemo(() => {
    const groups: Record<string, ComponentItem[]> = {}

    for (const node of nodes) {
      if (node.type === 'trustZone') continue
      const nodeType = node.type || 'process'
      if (!groups[nodeType]) groups[nodeType] = []
      groups[nodeType].push({
        id: node.id,
        label: node.data.label || nodeType,
        type: nodeType,
        targetType: nodeType === 'systemScope' ? 'systemScope' : 'component',
      })
    }

    return groups
  }, [nodes])

  // Data flows from edges — derive label from connected nodes when unnamed
  const nodeLabels = useMemo(() => {
    const map = new Map<string, string>()
    for (const node of nodes) map.set(node.id, node.data.label || node.id)
    return map
  }, [nodes])

  const dataFlows = useMemo(
    () =>
      edges
        .filter((e) => e.type === 'dataFlow')
        .map((e) => {
          const explicitLabel = e.data?.label as string | undefined
          const label = explicitLabel
            || `${nodeLabels.get(e.source) ?? '?'} → ${nodeLabels.get(e.target) ?? '?'}`
          return {
            id: e.id,
            label,
            type: 'dataFlow' as const,
            targetType: 'dataflow' as const,
          }
        }),
    [edges, nodeLabels]
  )

  // Find selected component info
  const selectedComponent = useMemo(() => {
    if (!selectedComponentId) return null
    for (const items of Object.values(componentsByType)) {
      const found = items.find((i) => i.id === selectedComponentId)
      if (found) return found
    }
    return dataFlows.find((f) => f.id === selectedComponentId) || null
  }, [selectedComponentId, componentsByType, dataFlows])

  // Threats for selected component
  const threatsForSelected = selectedComponentId
    ? guestEditor.getThreatsForTarget(selectedComponentId)
    : []

  // Sorted threats for display
  const sortedThreats = useMemo(() => {
    const sorted = [...threatsForSelected]
    sorted.sort((a, b) => {
      switch (sortField) {
        case 'status':
          return (STATUS_SORT_ORDER[a.status] ?? 99) - (STATUS_SORT_ORDER[b.status] ?? 99)
        case 'severity':
          return (SEVERITY_SORT_ORDER[a.severity] ?? 99) - (SEVERITY_SORT_ORDER[b.severity] ?? 99)
        case 'name':
          return a.name.localeCompare(b.name)
      }
    })
    return sorted
  }, [threatsForSelected, sortField])

  // Find selected threat
  const selectedThreat = selectedThreatId
    ? threatsForSelected.find((t) => t.id === selectedThreatId) || null
    : null

  // Countermeasures for selected threat
  const countermeasuresForThreat = selectedThreatId
    ? guestEditor.getCountermeasuresForThreat(selectedThreatId)
    : []

  const handleSelectComponent = (componentId: string) => {
    setSelectedComponentId(componentId)
    setSelectedThreatId(null)
  }

  const handleSelectThreat = (threatId: string) => {
    setSelectedThreatId(threatId)
  }

  const handleAddThreat = () => {
    setEditingThreat(undefined)
    setShowThreatDialog(true)
  }

  const handleEditThreat = (threat: GuestThreat) => {
    setEditingThreat(threat)
    setShowThreatDialog(true)
  }

  const handleDeleteThreat = (threatId: string) => {
    guestEditor.removeThreat(threatId)
    if (selectedThreatId === threatId) {
      setSelectedThreatId(null)
    }
  }

  const handleAddCountermeasure = () => {
    setEditingCountermeasure(undefined)
    setShowCountermeasureDialog(true)
  }

  const handleEditCountermeasure = (countermeasure: GuestCountermeasure) => {
    setEditingCountermeasure(countermeasure)
    setShowCountermeasureDialog(true)
  }

  const handleDeleteCountermeasure = (countermeasureId: string) => {
    guestEditor.removeCountermeasure(countermeasureId)
  }

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Subheader */}
      <div className="flex items-center gap-3 px-4 py-2 border-b bg-muted/30">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate('/guest')}
          className="gap-1.5"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Diagram
        </Button>
        <div className="h-4 w-px bg-border" />
        <h2 className="text-sm font-medium">Threat Analysis</h2>
      </div>

      {/* 3-column layout */}
      <div className="min-h-0 flex-1 overflow-hidden h-full">
        <ResizablePanelGroup orientation="horizontal">
          {/* Column 1: Components & Zones */}
          <ResizablePanel defaultSize="25%" minSize="15%" maxSize="35%">
            <div className="h-full flex flex-col border-r">
              <div className="px-3 py-2 border-b bg-muted/20">
                <h3 className="text-sm font-medium">Components</h3>
                <p className="text-xs text-muted-foreground">
                  {nodes.filter((n) => n.type !== 'trustZone').length} components,{' '}
                  {dataFlows.length} flows
                </p>
              </div>
              <ScrollArea className="flex-1">
                <div className="p-2 space-y-3">
                  {Object.entries(componentsByType).map(([nodeType, items]) => {
                    const Icon = NODE_TYPE_ICON[nodeType] || Cog
                    const groupLabel = NODE_TYPE_LABELS[nodeType] || nodeType
                    return (
                      <div key={nodeType}>
                        <div className="flex items-center gap-1.5 px-2 py-1 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                          <Icon className="h-3 w-3" />
                          {groupLabel}
                        </div>
                        <div className="space-y-0.5">
                          {items.map((item) => {
                            const threatCount = guestEditor.getThreatCount(item.id)
                            return (
                              <button
                                key={item.id}
                                onClick={() => handleSelectComponent(item.id)}
                                className={cn(
                                  'w-full flex items-center justify-between gap-2 px-2 py-1.5 rounded-md text-sm text-left hover:bg-muted/50',
                                  selectedComponentId === item.id && 'bg-muted'
                                )}
                              >
                                <span className="truncate">{item.label}</span>
                                {threatCount > 0 && (
                                  <Badge
                                    variant="secondary"
                                    className="h-5 px-1.5 text-xs shrink-0"
                                  >
                                    {threatCount}
                                  </Badge>
                                )}
                              </button>
                            )
                          })}
                        </div>
                      </div>
                    )
                  })}

                  {/* Data Flows section */}
                  {dataFlows.length > 0 && (
                    <div>
                      <div className="flex items-center gap-1.5 px-2 py-1 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                        <ArrowRight className="h-3 w-3" />
                        Data Flows
                      </div>
                      <div className="space-y-0.5">
                        {dataFlows.map((flow) => {
                          const threatCount = guestEditor.getThreatCount(flow.id)
                          return (
                            <button
                              key={flow.id}
                              onClick={() => handleSelectComponent(flow.id)}
                              className={cn(
                                'w-full flex items-center justify-between gap-2 px-2 py-1.5 rounded-md text-sm text-left hover:bg-muted/50',
                                selectedComponentId === flow.id && 'bg-muted'
                              )}
                            >
                              <span className="truncate">{flow.label}</span>
                              {threatCount > 0 && (
                                <Badge
                                  variant="secondary"
                                  className="h-5 px-1.5 text-xs shrink-0"
                                >
                                  {threatCount}
                                </Badge>
                              )}
                            </button>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {Object.keys(componentsByType).length === 0 &&
                    dataFlows.length === 0 && (
                      <p className="text-xs text-muted-foreground px-2 py-4 text-center">
                        No components in the diagram yet. Add components on the
                        canvas first.
                      </p>
                    )}
                </div>
              </ScrollArea>
            </div>
          </ResizablePanel>

          <ResizableHandle withHandle />

          {/* Column 2: Threats for selected component */}
          <ResizablePanel defaultSize="35%" minSize="20%" maxSize="55%">
            <div className="h-full flex flex-col border-r">
              <div className="px-3 py-2 border-b bg-muted/20 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-medium">
                    {selectedComponent
                      ? `Threats — ${selectedComponent.label}`
                      : 'Threats'}
                  </h3>
                  {selectedComponent && (
                    <p className="text-xs text-muted-foreground">
                      {threatsForSelected.length} threat
                      {threatsForSelected.length !== 1 ? 's' : ''}
                    </p>
                  )}
                </div>
                {selectedComponent && (
                  <div className="flex items-center gap-1.5">
                    {threatsForSelected.length > 1 && (
                      <Select value={sortField} onValueChange={(v) => setSortField(v as ThreatSortField)}>
                        <SelectTrigger className="h-7 w-[110px] text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {SORT_OPTIONS.map((opt) => (
                            <SelectItem key={opt.value} value={opt.value}>
                              Sort: {opt.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    )}
                    <Button size="sm" variant="outline" onClick={handleAddThreat} className="gap-1">
                      <Plus className="h-3 w-3" />
                      Add
                    </Button>
                  </div>
                )}
              </div>
              <ScrollArea className="flex-1">
                <div className="p-2">
                  {!selectedComponent ? (
                    <p className="text-xs text-muted-foreground px-2 py-4 text-center">
                      Select a component to view its threats.
                    </p>
                  ) : threatsForSelected.length === 0 ? (
                    <p className="text-xs text-muted-foreground px-2 py-4 text-center">
                      No threats for this component. Click "Add" to create one.
                    </p>
                  ) : (
                    <div className="space-y-1">
                      {sortedThreats.map((threat) => {
                        const countermeasureCount =
                          guestEditor.getCountermeasureCount(threat.id)
                        const warning = getThreatWarning(threat, countermeasureCount)
                        return (
                          <div
                            key={threat.id}
                            role="button"
                            tabIndex={0}
                            onClick={() => handleSelectThreat(threat.id)}
                            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleSelectThreat(threat.id) } }}
                            className={cn(
                              'w-full flex items-center justify-between gap-2 p-2 rounded-md text-sm text-left hover:bg-muted/50 cursor-pointer group',
                              selectedThreatId === threat.id && 'bg-muted'
                            )}
                          >
                            <div className="flex items-center gap-2 min-w-0">
                              <Badge
                                variant="secondary"
                                className={cn(
                                  'shrink-0 text-xs capitalize',
                                  STATUS_COLORS[threat.status]
                                )}
                              >
                                {threat.status}
                              </Badge>
                              <Badge
                                variant="secondary"
                                className={cn(
                                  'shrink-0 text-xs',
                                  SEVERITY_COLORS[threat.severity]
                                )}
                              >
                                {threat.severity}
                              </Badge>
                              {threat.category && STRIDE_CONFIG[threat.category] && (
                                <Badge
                                  variant="outline"
                                  className="shrink-0 text-xs border"
                                  style={{
                                    color: STRIDE_CONFIG[threat.category].color,
                                    borderColor: STRIDE_CONFIG[threat.category].color,
                                  }}
                                >
                                  {STRIDE_CONFIG[threat.category].label}
                                </Badge>
                              )}
                              <span className="truncate">{threat.name}</span>
                            </div>
                            <div className="flex items-center gap-1 shrink-0">
                              {warning && (
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
                                  </TooltipTrigger>
                                  <TooltipContent side="top">
                                    <p className="text-xs">{warning}</p>
                                  </TooltipContent>
                                </Tooltip>
                              )}
                              {countermeasureCount > 0 && (
                                <Badge
                                  variant="outline"
                                  className="h-5 px-1.5 text-xs gap-0.5"
                                >
                                  <Shield className="h-2.5 w-2.5" />
                                  {countermeasureCount}
                                </Badge>
                              )}
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 touch:opacity-100"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  handleEditThreat(threat)
                                }}
                              >
                                <Pencil className="h-3 w-3" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 touch:opacity-100 text-muted-foreground hover:text-red-600"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  handleDeleteThreat(threat.id)
                                }}
                              >
                                <Trash2 className="h-3 w-3" />
                              </Button>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              </ScrollArea>
            </div>
          </ResizablePanel>

          <ResizableHandle withHandle />

          {/* Column 3: Countermeasures for selected threat */}
          <ResizablePanel defaultSize="40%" minSize="20%">
            <div className="h-full flex flex-col">
              <div className="px-3 py-2 border-b bg-muted/20 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-medium">
                    {selectedThreat
                      ? `Countermeasures — ${selectedThreat.name}`
                      : 'Countermeasures'}
                  </h3>
                  {selectedThreat && (
                    <p className="text-xs text-muted-foreground">
                      {countermeasuresForThreat.length} countermeasure
                      {countermeasuresForThreat.length !== 1 ? 's' : ''}
                    </p>
                  )}
                </div>
                {selectedThreat && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={handleAddCountermeasure}
                    className="gap-1"
                  >
                    <Plus className="h-3 w-3" />
                    Add
                  </Button>
                )}
              </div>
              <ScrollArea className="flex-1">
                <div className="p-2">
                  {selectedThreat && selectedThreat.status !== 'mitigate' && selectedThreat.status !== 'open' && (
                    <div className="flex items-start gap-2 p-2 mb-2 rounded-md bg-muted/50 border text-xs text-muted-foreground">
                      <Info className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                      <span>
                        This threat&apos;s status is &ldquo;{GUEST_THREAT_STATUS_OPTIONS.find((o) => o.value === selectedThreat.status)?.label ?? selectedThreat.status}&rdquo; — countermeasures are optional.
                      </span>
                    </div>
                  )}
                  {!selectedThreat ? (
                    <p className="text-xs text-muted-foreground px-2 py-4 text-center">
                      Select a threat to view its countermeasures.
                    </p>
                  ) : countermeasuresForThreat.length === 0 ? (
                    <p className="text-xs text-muted-foreground px-2 py-4 text-center">
                      No countermeasures yet. Click &ldquo;Add&rdquo; to create one.
                    </p>
                  ) : (
                    <div className="space-y-1">
                      {countermeasuresForThreat.map((countermeasure) => (
                        <div
                          key={countermeasure.id}
                          className="flex items-center justify-between gap-2 p-2 rounded-md border bg-card text-sm group"
                        >
                          <div className="flex items-start gap-2 min-w-0">
                            <div className="flex flex-wrap gap-1 shrink-0 pt-0.5">
                              {countermeasure.controlFunction.map((fn) => (
                                <Badge
                                  key={fn}
                                  variant="secondary"
                                  className={cn(
                                    'text-xs capitalize',
                                    CONTROL_FUNCTION_COLORS[fn]
                                  )}
                                >
                                  {fn}
                                </Badge>
                              ))}
                              <Badge
                                variant="outline"
                                className={cn(
                                  'text-xs',
                                  CONTROL_NATURE_COLORS[countermeasure.controlNature]
                                )}
                              >
                                {CONTROL_NATURE_LABELS[countermeasure.controlNature]}
                              </Badge>
                            </div>
                            <div className="min-w-0">
                              <span className="truncate block">
                                {countermeasure.name}
                              </span>
                              {countermeasure.description && (
                                <span className="text-xs text-muted-foreground truncate block">
                                  {countermeasure.description}
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-1 shrink-0">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 touch:opacity-100"
                              onClick={() =>
                                handleEditCountermeasure(countermeasure)
                              }
                            >
                              <Pencil className="h-3 w-3" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 touch:opacity-100 text-muted-foreground hover:text-red-600"
                              onClick={() =>
                                handleDeleteCountermeasure(countermeasure.id)
                              }
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </ScrollArea>
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>

      {/* Dialogs */}
      {selectedComponent && (
        <GuestThreatDialog
          open={showThreatDialog}
          onOpenChange={setShowThreatDialog}
          targetId={selectedComponent.id}
          targetType={selectedComponent.targetType}
          targetName={selectedComponent.label}
          editThreat={editingThreat}
        />
      )}

      {selectedThreat && (
        <GuestCountermeasureDialog
          open={showCountermeasureDialog}
          onOpenChange={setShowCountermeasureDialog}
          threatId={selectedThreat.id}
          threatName={selectedThreat.name}
          editCountermeasure={editingCountermeasure}
        />
      )}
    </div>
  )
}
