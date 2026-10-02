import { useState } from 'react'
import { toast } from 'sonner'
import {
  Plus,
  RefreshCw,
  Trash2,
  ChevronRight,
  Search,
  Loader2,
  LayoutGrid,
  Table2,
  CheckSquare,
  Square,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationNext,
  PaginationPrevious,
} from '@/components/ui/pagination'
import {
  useRisks,
  useRisk,
  useCreateRisk,
  useUpdateRisk,
  useDeleteRisk,
  useRecalculateRisk,
  useScoringMethods,
  useBulkUpdateRisks,
  RISK_PAGE_SIZES,
  DEFAULT_RISK_PAGE_SIZE,
} from '@/features/threat-models/api/risks'
import type {
  Risk,
  RiskLevel,
  RiskResponse,
  ScoringMethodKey,
  CreateRiskInput,
  ScoringMethod,
} from '@/types/risk'
import type { ComponentThreat } from '@/features/dfd-editor/types/threat-analysis'
import { isActiveThreat } from '@/types/triage'
import { useWorkspace } from '@/contexts/WorkspaceContext'
import { useOrganizationMembers } from '@/features/organization/api/organizations'

interface RiskAnalysisTabProps {
  threatModelId: string
  componentThreats: ComponentThreat[]
  riskScoringMethod: ScoringMethodKey
  onScoringMethodChange: (method: ScoringMethodKey) => void
}

type ViewMode = 'table' | 'kanban'

const KANBAN_COLUMNS: { response: RiskResponse | null; label: string; color: string }[] = [
  { response: null, label: 'Unresponded', color: 'border-gray-300 bg-gray-50' },
  { response: 'mitigate', label: 'Mitigate', color: 'border-blue-300 bg-blue-50' },
  { response: 'transfer', label: 'Transfer', color: 'border-yellow-300 bg-yellow-50' },
  { response: 'accept', label: 'Accept', color: 'border-purple-300 bg-purple-50' },
  { response: 'avoid', label: 'Avoid', color: 'border-green-300 bg-green-50' },
]

const LEVEL_COLORS: Record<RiskLevel, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-green-100 text-green-800 border-green-200',
}

const RESPONSE_COLORS: Record<string, string> = {
  accept: 'bg-purple-100 text-purple-800 border-purple-200',
  mitigate: 'bg-blue-100 text-blue-800 border-blue-200',
  transfer: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  avoid: 'bg-green-100 text-green-800 border-green-200',
}

const RESPONSE_LABELS: Record<string, string> = {
  accept: 'Accept',
  mitigate: 'Mitigate',
  transfer: 'Transfer',
  avoid: 'Avoid',
}

function LevelBadge({ level }: { level: RiskLevel | null }) {
  if (!level) return <span className="text-muted-foreground text-sm">--</span>
  return (
    <Badge variant="outline" className={LEVEL_COLORS[level]}>
      {level}
    </Badge>
  )
}

function ResponseBadge({ response }: { response: RiskResponse | null }) {
  if (!response) {
    return <span className="text-muted-foreground text-sm">—</span>
  }
  return (
    <Badge variant="outline" className={RESPONSE_COLORS[response]}>
      {RESPONSE_LABELS[response]}
    </Badge>
  )
}

function ScoreDisplay({ score, level }: { score: number | null; level: RiskLevel | null }) {
  if (score === null) return <span className="text-muted-foreground">--</span>
  return (
    <div className="flex items-center gap-2">
      <span className="font-mono text-sm font-medium">{score}</span>
      <LevelBadge level={level} />
    </div>
  )
}

// ─── Scoring metadata form ────────────────────────────────────────────────────

function ScoringMetadataForm({
  method,
  metadata,
  onChange,
}: {
  method: ScoringMethod | undefined
  metadata: Record<string, unknown>
  onChange: (metadata: Record<string, unknown>) => void
}) {
  if (!method) return null
  return (
    <div className="space-y-3">
      {Object.entries(method.metadataSchema).map(([fieldKey, fieldSchema]) => {
        const requiredIndicator = fieldSchema.required ? <span className="text-destructive ml-0.5">*</span> : null
        if (fieldSchema.type === 'enum' && fieldSchema.values) {
          return (
            <div key={fieldKey} className="space-y-1">
              <Label className="capitalize">{fieldKey.replace(/_/g, ' ')}{requiredIndicator}</Label>
              <Select
                value={(metadata[fieldKey] as string) || ''}
                onValueChange={(value) => onChange({ ...metadata, [fieldKey]: value })}
              >
                <SelectTrigger>
                  <SelectValue placeholder={`Select ${fieldKey.replace(/_/g, ' ')}`} />
                </SelectTrigger>
                <SelectContent>
                  {fieldSchema.values.map((value) => (
                    <SelectItem key={value} value={value}>
                      <span className="capitalize">{value.replace(/_/g, ' ')}</span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )
        }
        if (fieldSchema.type === 'text') {
          return (
            <div key={fieldKey} className="space-y-1">
              <Label className="capitalize">{fieldKey.replace(/_/g, ' ')}{requiredIndicator}</Label>
              <Textarea
                value={(metadata[fieldKey] as string) || ''}
                onChange={(e) => onChange({ ...metadata, [fieldKey]: e.target.value })}
                rows={2}
              />
            </div>
          )
        }
        if (fieldSchema.type === 'number') {
          return (
            <div key={fieldKey} className="space-y-1">
              <Label className="capitalize">{fieldKey.replace(/_/g, ' ')}{requiredIndicator}</Label>
              <Input
                type="number"
                value={(metadata[fieldKey] as number) ?? ''}
                onChange={(e) =>
                  onChange({ ...metadata, [fieldKey]: e.target.value ? Number(e.target.value) : undefined })
                }
                min={fieldSchema.min}
                max={fieldSchema.max}
              />
            </div>
          )
        }
        return null
      })}
    </div>
  )
}

// ─── Threat picker ────────────────────────────────────────────────────────────

function ThreatPicker({
  componentThreats,
  selectedComponentThreatIds,
  selectedFlowThreatIds,
  onToggle,
}: {
  componentThreats: ComponentThreat[]
  selectedComponentThreatIds: number[]
  selectedFlowThreatIds: number[]
  onToggle: (backendId: number, threatType: 'component' | 'dataflow') => void
}) {
  const [pickerOpen, setPickerOpen] = useState(false)
  const [filter, setFilter] = useState('')

  const activeThreats = componentThreats.filter((t) => isActiveThreat(t.triageStatus) && t.backendThreatId)
  const selectedCount = selectedComponentThreatIds.length + selectedFlowThreatIds.length

  if (activeThreats.length === 0) {
    return <p className="text-sm text-muted-foreground py-2">No threats available to link.</p>
  }

  const filteredThreats = filter
    ? activeThreats.filter((t) =>
        (t.threatName || '').toLowerCase().includes(filter.toLowerCase())
      )
    : activeThreats

  return (
    <>
      <Button
        type="button"
        variant="outline"
        className="w-full justify-between"
        onClick={() => setPickerOpen(true)}
      >
        <span>
          {selectedCount > 0
            ? `${selectedCount} threat${selectedCount === 1 ? '' : 's'} selected`
            : 'Select threats...'}
        </span>
        <ChevronRight className="h-4 w-4" />
      </Button>
      <Dialog open={pickerOpen} onOpenChange={(open) => { setPickerOpen(open); if (!open) setFilter('') }}>
        <DialogContent className="max-w-lg max-h-[80vh] flex flex-col">
          <DialogHeader>
            <DialogTitle>Link Threats</DialogTitle>
            <DialogDescription>
              Select threats to associate with this risk. {selectedCount > 0 && `${selectedCount} selected.`}
            </DialogDescription>
          </DialogHeader>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter threats..."
              className="h-8 pl-7 text-sm"
            />
          </div>
          <div className="flex-1 overflow-y-auto border rounded-md min-h-0">
            {filteredThreats.length === 0 ? (
              <p className="text-sm text-muted-foreground px-3 py-2">No matching threats.</p>
            ) : (
              filteredThreats.map((threat) => {
                const isComponent = threat.threatType !== 'dataflow'
                const selectedIds = isComponent ? selectedComponentThreatIds : selectedFlowThreatIds
                const isSelected = selectedIds.includes(threat.backendThreatId!)
                return (
                  <label
                    key={threat.id}
                    className="flex items-center gap-2 px-3 py-2 hover:bg-muted/50 cursor-pointer border-b last:border-b-0"
                  >
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => onToggle(threat.backendThreatId!, threat.threatType as 'component' | 'dataflow')}
                      className="rounded"
                    />
                    <div className="flex-1 min-w-0">
                      <span className="text-sm truncate block">
                        {threat.threatName || `Threat #${threat.backendThreatId}`}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {isComponent
                          ? `Component${threat.componentName ? `: ${threat.componentName}` : ''}`
                          : `Flow${threat.dataflowLabel ? `: ${threat.dataflowLabel}` : ''}`}
                      </span>
                    </div>
                  </label>
                )
              })
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPickerOpen(false)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

// ─── Add Risk dialog ──────────────────────────────────────────────────────────

function AddRiskDialog({
  open,
  onOpenChange,
  threatModelId,
  componentThreats,
  scoringMethod,
  activeScoringMethod,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string
  componentThreats: ComponentThreat[]
  scoringMethod: ScoringMethodKey
  activeScoringMethod: ScoringMethod | undefined
}) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [riskResponse, setRiskResponse] = useState<RiskResponse | null>(null)
  const [owner, setOwner] = useState<number | null>(null)
  const [scoringMetadata, setScoringMetadata] = useState<Record<string, unknown>>({})
  const [inherentScore, setInherentScore] = useState<number | ''>('')
  const [selectedComponentThreatIds, setSelectedComponentThreatIds] = useState<number[]>([])
  const [selectedFlowThreatIds, setSelectedFlowThreatIds] = useState<number[]>([])

  const createRisk = useCreateRisk(threatModelId)
  const { currentOrganization } = useWorkspace()
  const { data: orgMembers = [] } = useOrganizationMembers(currentOrganization?.id ?? 0)
  const isCustom = scoringMethod === 'custom' || !activeScoringMethod?.available

  const handleToggleThreat = (backendId: number, threatType: 'component' | 'dataflow') => {
    if (threatType === 'component') {
      setSelectedComponentThreatIds((prev) =>
        prev.includes(backendId) ? prev.filter((id) => id !== backendId) : [...prev, backendId]
      )
    } else {
      setSelectedFlowThreatIds((prev) =>
        prev.includes(backendId) ? prev.filter((id) => id !== backendId) : [...prev, backendId]
      )
    }
  }

  const resetForm = () => {
    setName('')
    setDescription('')
    setRiskResponse(null)
    setOwner(null)
    setScoringMetadata({})
    setInherentScore('')
    setSelectedComponentThreatIds([])
    setSelectedFlowThreatIds([])
  }

  const handleSubmit = () => {
    const input: CreateRiskInput = {
      name,
      description,
      scoringMetadata,
      response: riskResponse,
      owner,
      componentThreatIds: selectedComponentThreatIds,
      flowThreatIds: selectedFlowThreatIds,
    }
    if (isCustom && inherentScore !== '') input.inherentScore = Number(inherentScore)
    createRisk.mutate(input, {
      onSuccess: () => { onOpenChange(false); resetForm() },
      onError: (error) => {
        let message = 'Failed to create risk.'
        if (error instanceof Error && 'data' in error && error.data && typeof error.data === 'object') {
          const data = error.data as Record<string, unknown>
          const fieldMessages = Object.values(data)
            .map((v) => (Array.isArray(v) ? v.join(', ') : String(v)))
          if (fieldMessages.length) message = fieldMessages.join(' ')
        }
        toast.error(message)
      },
    })
  }

  const hasRequiredMetadata = isCustom
    ? inherentScore !== ''
    : !activeScoringMethod || Object.entries(activeScoringMethod.metadataSchema)
        .filter(([, field]) => field.required)
        .every(([key]) => {
          const value = scoringMetadata[key]
          return value !== undefined && value !== null && value !== ''
        })

  const canSubmit = !!name.trim() && hasRequiredMetadata

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Add Risk</DialogTitle>
          <DialogDescription>
            Define a new risk and optionally link it to existing threats.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1">
            <Label>Name<span className="text-destructive ml-0.5">*</span></Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g., Data Breach via API Exploitation" />
          </div>
          <div className="space-y-1">
            <Label>Description</Label>
            <Textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>Response</Label>
              <Select value={riskResponse ?? '_none'} onValueChange={(v) => setRiskResponse(v === '_none' ? null : v as RiskResponse)}>
                <SelectTrigger>
                  <SelectValue placeholder="Select response…" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="_none">None</SelectItem>
                  {Object.entries(RESPONSE_LABELS).map(([val, label]) => (
                    <SelectItem key={val} value={val}>{label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>Owner</Label>
              <Select value={owner?.toString() ?? '_none'} onValueChange={(v) => setOwner(v === '_none' ? null : Number(v))}>
                <SelectTrigger>
                  <SelectValue placeholder="Select owner…" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="_none">No owner</SelectItem>
                  {orgMembers.map((member) => (
                    <SelectItem key={member.user} value={member.user.toString()}>
                      {member.userEmail}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          {isCustom ? (
            <div className="space-y-1">
              <Label>Inherent Score (0–100)<span className="text-destructive ml-0.5">*</span></Label>
              <Input type="number" min={0} max={100} value={inherentScore} onChange={(e) => setInherentScore(e.target.value ? Number(e.target.value) : '')} />
            </div>
          ) : (
            <ScoringMetadataForm method={activeScoringMethod} metadata={scoringMetadata} onChange={setScoringMetadata} />
          )}
          <div className="space-y-1">
            <Label>Link Threats (optional)</Label>
            <ThreatPicker
              componentThreats={componentThreats}
              selectedComponentThreatIds={selectedComponentThreatIds}
              selectedFlowThreatIds={selectedFlowThreatIds}
              onToggle={handleToggleThreat}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={handleSubmit} disabled={!canSubmit || createRisk.isPending}>
            {createRisk.isPending && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
            Create Risk
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ─── Risk detail panel ────────────────────────────────────────────────────────

function RiskDetailPanel({
  risk,
  threatModelId,
  onClose,
}: {
  risk: Risk
  threatModelId: string
  onClose: () => void
}) {
  const { data: riskDetail } = useRisk(threatModelId, risk.id)
  const displayRisk = riskDetail ?? risk
  const updateRisk = useUpdateRisk(threatModelId)
  const { data: scoringMethods } = useScoringMethods()
  const scoringMethodLabel =
    scoringMethods?.find((m) => m.key === displayRisk.scoringMethod)?.label ??
    displayRisk.scoringMethod.replace(/_/g, ' ')

  const handleResponseChange = (newResponse: string) => {
    updateRisk.mutate({ riskId: risk.id, data: { response: newResponse as RiskResponse } })
  }

  return (
    <Card className="border-l-2 border-l-primary">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg">{displayRisk.name}</CardTitle>
          <Button variant="ghost" size="sm" onClick={onClose}>&times;</Button>
        </div>
        {displayRisk.description && (
          <p className="text-sm text-muted-foreground">{displayRisk.description}</p>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-xs text-muted-foreground mb-1">Inherent Risk</p>
            <ScoreDisplay score={displayRisk.inherentScore} level={displayRisk.inherentLevel} />
          </div>
          <div>
            <p className="text-xs text-muted-foreground mb-1">Residual Risk</p>
            <ScoreDisplay score={displayRisk.residualScore} level={displayRisk.residualLevel} />
          </div>
        </div>

        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Response</p>
          <div className="flex items-center gap-2">
            <Select value={displayRisk.response ?? '_none'} onValueChange={(v) => handleResponseChange(v === '_none' ? '' : v)}>
              <SelectTrigger className="h-8 w-[160px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="_none">Unresponded</SelectItem>
                {Object.entries(RESPONSE_LABELS).map(([val, label]) => (
                  <SelectItem key={val} value={val}>{label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {displayRisk.ownerEmail && (
          <div>
            <p className="text-xs text-muted-foreground">Owner</p>
            <p className="text-sm">{displayRisk.ownerEmail}</p>
          </div>
        )}

        {displayRisk.threats && displayRisk.threats.length > 0 && (
          <div>
            <p className="text-xs text-muted-foreground mb-2">Linked Threats ({displayRisk.threats.length})</p>
            <div className="space-y-1">
              {displayRisk.threats.map((threat) => (
                <div key={threat.riskThreatId} className="flex items-center justify-between text-sm border rounded px-2 py-1">
                  <span className="truncate flex-1">{threat.threatName || `Threat #${threat.threatId}`}</span>
                  <div className="flex items-center gap-1.5 ml-2">
                    <Badge variant="outline" className="text-xs">{threat.threatType}</Badge>
                    <Badge variant="outline" className={
                      threat.status === 'mitigated' ? 'bg-green-50 text-green-700' :
                      threat.status === 'accepted' ? 'bg-blue-50 text-blue-700' :
                      'bg-red-50 text-red-700'
                    }>{threat.status}</Badge>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="text-xs text-muted-foreground pt-2 border-t">
          <p>Method: {scoringMethodLabel}</p>
          <p>Created: {new Date(displayRisk.createdAt).toLocaleDateString()}</p>
        </div>
      </CardContent>
    </Card>
  )
}

// ─── Kanban board ─────────────────────────────────────────────────────────────

function KanbanCard({
  risk,
  isSelected,
  onSelect,
  onDelete,
}: {
  risk: Risk
  isSelected: boolean
  onSelect: () => void
  onDelete: () => void
}) {
  return (
    <div
      className={`bg-white border rounded-lg p-3 shadow-sm cursor-pointer hover:shadow-md transition-shadow ${isSelected ? 'ring-2 ring-primary' : ''}`}
      onClick={onSelect}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <span className="text-sm font-medium leading-tight">{risk.name}</span>
        <Button
          variant="ghost"
          size="sm"
          className="h-5 w-5 p-0 shrink-0"
          onClick={(e) => { e.stopPropagation(); onDelete() }}
        >
          <Trash2 className="h-3 w-3 text-muted-foreground" />
        </Button>
      </div>
      <div className="flex items-center gap-1.5 flex-wrap">
        <LevelBadge level={risk.inherentLevel} />
      </div>
      {risk.ownerEmail && (
        <p className="text-xs text-muted-foreground mt-1 truncate">{risk.ownerEmail}</p>
      )}
    </div>
  )
}

function KanbanBoard({
  risks,
  selectedRiskId,
  onSelectRisk,
  onDeleteRisk,
  threatModelId,
}: {
  risks: Risk[]
  selectedRiskId: number | null
  onSelectRisk: (id: number) => void
  onDeleteRisk: (id: number) => void
  threatModelId: string
}) {
  const updateRisk = useUpdateRisk(threatModelId)

  const handleDrop = (e: React.DragEvent, targetResponse: RiskResponse | null) => {
    e.preventDefault()
    const riskId = Number(e.dataTransfer.getData('riskId'))
    if (riskId) updateRisk.mutate({ riskId, data: { response: targetResponse } })
  }

  return (
    <div className="grid grid-cols-5 items-start gap-4">
      {KANBAN_COLUMNS.map((col) => {
        const colRisks = risks.filter((r) => r.response === col.response)
        return (
          <div
            key={col.response ?? '_none'}
            className={`rounded-lg border-2 ${col.color} p-3`}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => handleDrop(e, col.response)}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm font-semibold">{col.label}</span>
              <Badge variant="secondary" className="text-xs">{colRisks.length}</Badge>
            </div>
            <div className="space-y-2">
              {colRisks.map((risk) => (
                <div
                  key={risk.id}
                  draggable
                  onDragStart={(e) => e.dataTransfer.setData('riskId', String(risk.id))}
                >
                  <KanbanCard
                    risk={risk}
                    isSelected={selectedRiskId === risk.id}
                    onSelect={() => onSelectRisk(risk.id)}
                    onDelete={() => onDeleteRisk(risk.id)}
                  />
                </div>
              ))}
              {colRisks.length === 0 && (
                <div className="border border-dashed rounded-md py-4 text-xs text-muted-foreground text-center">
                  Drop here
                </div>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── Bulk action bar ──────────────────────────────────────────────────────────

function BulkActionBar({
  selectedIds,
  threatModelId,
  onClear,
  isPaginated,
}: {
  selectedIds: number[]
  threatModelId: string
  onClear: () => void
  /** Select-all ticks the loaded rows, which is every row only when the register
      fits on one page. Past that the label has to say so. */
  isPaginated: boolean
}) {
  const bulkUpdate = useBulkUpdateRisks(threatModelId)
  const [bulkResponse, setBulkResponse] = useState<RiskResponse | ''>('')

  const handleApply = () => {
    if (!bulkResponse) return
    bulkUpdate.mutate(
      {
        riskIds: selectedIds,
        response: bulkResponse,
      },
      { onSuccess: onClear }
    )
  }

  return (
    <div className="flex items-center gap-3 p-3 bg-muted/60 border rounded-lg">
      <span className="text-sm font-medium">
        {selectedIds.length} selected{isPaginated && ' on this page'}
      </span>
      <Select value={bulkResponse} onValueChange={(v) => setBulkResponse(v as RiskResponse)}>
        <SelectTrigger className="h-8 w-[150px]">
          <SelectValue placeholder="Set response…" />
        </SelectTrigger>
        <SelectContent>
          {Object.entries(RESPONSE_LABELS).map(([val, label]) => (
            <SelectItem key={val} value={val}>{label}</SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Button size="sm" onClick={handleApply} disabled={!bulkResponse || bulkUpdate.isPending}>
        {bulkUpdate.isPending ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : null}
        Apply
      </Button>
      <Button size="sm" variant="ghost" onClick={onClear}>Clear</Button>
    </div>
  )
}

// ─── Table view ───────────────────────────────────────────────────────────────

function TableView({
  risks,
  selectedRiskId,
  selectedIds,
  onSelectRisk,
  onToggleSelect,
  onToggleSelectAll,
  onDeleteRisk,
  onRecalculateRisk,
  recalculatingRiskId,
}: {
  risks: Risk[]
  selectedRiskId: number | null
  selectedIds: number[]
  onSelectRisk: (id: number) => void
  onToggleSelect: (id: number) => void
  onToggleSelectAll: () => void
  onDeleteRisk: (id: number) => void
  onRecalculateRisk: (id: number) => void
  recalculatingRiskId: number | null
}) {
  const allSelected = risks.length > 0 && selectedIds.length === risks.length

  return (
    <div className="border rounded-lg">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[40px]">
              <button onClick={onToggleSelectAll} className="flex items-center">
                {allSelected
                  ? <CheckSquare className="h-4 w-4 text-primary" />
                  : <Square className="h-4 w-4 text-muted-foreground" />
                }
              </button>
            </TableHead>
            <TableHead>Name</TableHead>
            <TableHead className="w-[140px]">Inherent</TableHead>
            <TableHead className="w-[140px]">Residual</TableHead>
            <TableHead className="w-[120px]">Response</TableHead>
            <TableHead className="w-[140px]">Owner</TableHead>
            <TableHead className="w-[80px]">Threats</TableHead>
            <TableHead className="w-[100px]">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {risks.map((risk) => (
            <TableRow
              key={risk.id}
              className={`cursor-pointer ${selectedRiskId === risk.id ? 'bg-muted/50' : ''}`}
              onClick={() => onSelectRisk(risk.id)}
            >
              <TableCell onClick={(e) => e.stopPropagation()}>
                <Checkbox
                  checked={selectedIds.includes(risk.id)}
                  onCheckedChange={() => onToggleSelect(risk.id)}
                />
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <span className="font-medium">{risk.name}</span>
                  <ChevronRight className="h-3 w-3 text-muted-foreground" />
                </div>
              </TableCell>
              <TableCell>
                <ScoreDisplay score={risk.inherentScore} level={risk.inherentLevel} />
              </TableCell>
              <TableCell>
                <ScoreDisplay score={risk.residualScore} level={risk.residualLevel} />
              </TableCell>
              <TableCell>
                <ResponseBadge response={risk.response} />
              </TableCell>
              <TableCell className="text-sm text-muted-foreground truncate">
                {risk.ownerEmail ?? '—'}
              </TableCell>
              <TableCell className="text-center text-sm text-muted-foreground">
                {risk.threatCount}
              </TableCell>
              <TableCell className="whitespace-nowrap">
                <Button
                  variant="ghost"
                  size="sm"
                  title="Recalculate residual risk"
                  aria-label={`Recalculate residual risk for ${risk.name}`}
                  disabled={recalculatingRiskId === risk.id}
                  onClick={(e) => {
                    e.stopPropagation()
                    onRecalculateRisk(risk.id)
                  }}
                >
                  <RefreshCw className={`h-3.5 w-3.5 text-muted-foreground ${recalculatingRiskId === risk.id ? 'animate-spin' : ''}`} />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={(e) => { e.stopPropagation(); onDeleteRisk(risk.id) }}
                >
                  <Trash2 className="h-3.5 w-3.5 text-muted-foreground" />
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

// ─── Pagination ───────────────────────────────────────────────────────────────

/**
 * Props that make a `PaginationPrevious`/`PaginationNext` unusable at a boundary.
 *
 * Those render an `<a>`, which has no `disabled`: the component is built for
 * href-based paging, while this register drives state from `onClick`. Kept here
 * rather than patched into `components/ui/pagination.tsx` so that file stays a
 * verbatim copy of upstream.
 */
function boundaryProps(atBoundary: boolean) {
  return atBoundary
    ? {
        'aria-disabled': true,
        tabIndex: -1,
        className: 'pointer-events-none opacity-50',
      }
    : {}
}

function RegisterPagination({
  page,
  pageCount,
  pageSize,
  onPageChange,
  onPageSizeChange,
}: {
  page: number
  pageCount: number
  pageSize: number
  onPageChange: (page: number) => void
  onPageSizeChange: (pageSize: number) => void
}) {
  return (
    <div className="flex items-center justify-between gap-3 flex-wrap">
      <div className="flex items-center gap-2">
        <Label className="text-sm text-muted-foreground whitespace-nowrap">Per page:</Label>
        <Select value={String(pageSize)} onValueChange={(v) => onPageSizeChange(Number(v))}>
          <SelectTrigger className="h-8 w-[80px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {RISK_PAGE_SIZES.map((size) => (
              <SelectItem key={size} value={String(size)}>{size}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <Pagination className="mx-0 w-auto justify-end">
        <PaginationContent>
          <PaginationItem>
            <PaginationPrevious
              href="#"
              onClick={(e) => { e.preventDefault(); onPageChange(page - 1) }}
              {...boundaryProps(page <= 1)}
            />
          </PaginationItem>
          <PaginationItem>
            <span className="px-3 text-sm text-muted-foreground tabular-nums">
              Page {page} of {pageCount}
            </span>
          </PaginationItem>
          <PaginationItem>
            <PaginationNext
              href="#"
              onClick={(e) => { e.preventDefault(); onPageChange(page + 1) }}
              {...boundaryProps(page >= pageCount)}
            />
          </PaginationItem>
        </PaginationContent>
      </Pagination>
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export function RiskAnalysisTab({
  threatModelId,
  componentThreats,
  riskScoringMethod,
  onScoringMethodChange,
}: RiskAnalysisTabProps) {
  const [viewMode, setViewMode] = useState<ViewMode>('table')
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [selectedRiskId, setSelectedRiskId] = useState<number | null>(null)
  const [deleteRiskId, setDeleteRiskId] = useState<number | null>(null)
  const [selectedIds, setSelectedIds] = useState<number[]>([])
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState<number>(DEFAULT_RISK_PAGE_SIZE)

  const { data: riskPage, isLoading } = useRisks(threatModelId, { page, pageSize })
  const { data: scoringMethods } = useScoringMethods()
  const deleteRisk = useDeleteRisk(threatModelId)
  const recalculateRisk = useRecalculateRisk(threatModelId)

  // `risks` is one page; `totalRisks` is the register. Everything the user can
  // act on — select, bulk-update, drag between board columns — is scoped to the
  // page, because that is all the client has.
  const risks = riskPage?.results
  const totalRisks = riskPage?.count ?? 0
  const pageCount = Math.max(1, Math.ceil(totalRisks / pageSize))
  const firstRowNumber = (page - 1) * pageSize + 1
  const lastRowNumber = firstRowNumber + (risks?.length ?? 0) - 1

  const selectedRisk = risks?.find((r) => r.id === selectedRiskId)
  const activeScoringMethod = scoringMethods?.find((m) => m.key === riskScoringMethod)

  // Selection can only refer to rows that are loaded, so leaving the page drops
  // it rather than silently carrying ids the user can no longer see.
  const goToPage = (next: number) => {
    setPage(next)
    setSelectedIds([])
    setSelectedRiskId(null)
  }

  const changePageSize = (next: number) => {
    setPageSize(next)
    goToPage(1)
  }

  const handleDelete = () => {
    if (deleteRiskId === null) return
    deleteRisk.mutate(deleteRiskId, {
      onSuccess: () => {
        setDeleteRiskId(null)
        if (selectedRiskId === deleteRiskId) setSelectedRiskId(null)
        setSelectedIds((prev) => prev.filter((id) => id !== deleteRiskId))
        // Deleting a page's last row leaves `page` past the end. DRF answers an
        // out-of-range page with a 404 rather than an empty one, so step back
        // before the refetch asks for it.
        if (page > 1 && risks?.length === 1) goToPage(page - 1)
      },
    })
  }

  const handleToggleSelect = (id: number) => {
    setSelectedIds((prev) => prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id])
  }

  const handleToggleSelectAll = () => {
    if (!risks) return
    setSelectedIds(selectedIds.length === risks.length ? [] : risks.map((r) => r.id))
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-semibold">Risk Register</h2>
          <p className="text-sm text-muted-foreground">
            {totalRisks} risk{totalRisks !== 1 ? 's' : ''}
            {pageCount > 1 && ` — showing ${firstRowNumber}–${lastRowNumber}`}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Scoring method */}
          <div className="flex items-center gap-2">
            <Label className="text-sm text-muted-foreground whitespace-nowrap">Scoring:</Label>
            <Select value={riskScoringMethod} onValueChange={(v) => onScoringMethodChange(v as ScoringMethodKey)}>
              <SelectTrigger className="w-[220px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(scoringMethods ?? []).map((method) => (
                  <SelectItem key={method.key} value={method.key} disabled={!method.available}>
                    {method.label}{!method.available && ' (Coming Soon)'}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {/* View toggle */}
          <div className="flex border rounded-md overflow-hidden">
            <Button
              variant={viewMode === 'table' ? 'default' : 'ghost'}
              size="sm"
              className="rounded-none"
              onClick={() => setViewMode('table')}
            >
              <Table2 className="h-4 w-4" />
            </Button>
            <Button
              variant={viewMode === 'kanban' ? 'default' : 'ghost'}
              size="sm"
              className="rounded-none"
              onClick={() => setViewMode('kanban')}
            >
              <LayoutGrid className="h-4 w-4" />
            </Button>
          </div>
          <Button onClick={() => setAddDialogOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            Add Risk
          </Button>
        </div>
      </div>

      {/* Bulk action bar */}
      {selectedIds.length > 0 && viewMode === 'table' && (
        <BulkActionBar
          selectedIds={selectedIds}
          threatModelId={threatModelId}
          onClear={() => setSelectedIds([])}
          isPaginated={pageCount > 1}
        />
      )}

      {/* An empty column does not mean no risks carry that response — they may
          be on another page. Nothing on the board itself shows that. */}
      {viewMode === 'kanban' && pageCount > 1 && (
        <p className="text-sm text-muted-foreground">
          Board shows risks {firstRowNumber}–{lastRowNumber} of {totalRisks}. Column counts
          are for this page — raise the page size to see more of the register at once.
        </p>
      )}

      {/* Empty state */}
      {!risks || risks.length === 0 ? (
        <Card className="p-12 text-center">
          <p className="text-muted-foreground mb-4">
            No risks defined yet. Add a risk manually to get started.
          </p>
          <div className="flex items-center justify-center gap-3">
            <Button onClick={() => setAddDialogOpen(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Add Risk
            </Button>
          </div>
        </Card>
      ) : (
        <>
        <div className="flex gap-6">
          {/* Main content */}
          <div className={`flex-1 min-w-0 ${selectedRisk && viewMode === 'table' ? 'max-w-[60%]' : ''}`}>
            {viewMode === 'table' ? (
              <TableView
                risks={risks}
                selectedRiskId={selectedRiskId}
                selectedIds={selectedIds}
                onSelectRisk={setSelectedRiskId}
                onToggleSelect={handleToggleSelect}
                onToggleSelectAll={handleToggleSelectAll}
                onDeleteRisk={setDeleteRiskId}
                onRecalculateRisk={(riskId) => recalculateRisk.mutate(riskId)}
                recalculatingRiskId={recalculateRisk.isPending ? recalculateRisk.variables ?? null : null}
              />
            ) : (
              <KanbanBoard
                risks={risks}
                selectedRiskId={selectedRiskId}
                onSelectRisk={setSelectedRiskId}
                onDeleteRisk={setDeleteRiskId}
                threatModelId={threatModelId}
              />
            )}
          </div>

          {/* Detail panel (table view only) */}
          {selectedRisk && viewMode === 'table' && (
            <div className="w-[40%] shrink-0">
              <RiskDetailPanel
                risk={selectedRisk}
                threatModelId={threatModelId}
                onClose={() => setSelectedRiskId(null)}
              />
            </div>
          )}
        </div>

        {/* Kept visible at one page too, once the size has been changed, so the
            control that got the user there can also take them back. */}
        {(pageCount > 1 || pageSize !== DEFAULT_RISK_PAGE_SIZE) && (
          <RegisterPagination
            page={page}
            pageCount={pageCount}
            pageSize={pageSize}
            onPageChange={goToPage}
            onPageSizeChange={changePageSize}
          />
        )}
        </>
      )}

      {/* Detail panel for kanban (below board) */}
      {selectedRisk && viewMode === 'kanban' && (
        <RiskDetailPanel
          risk={selectedRisk}
          threatModelId={threatModelId}
          onClose={() => setSelectedRiskId(null)}
        />
      )}

      <AddRiskDialog
        open={addDialogOpen}
        onOpenChange={setAddDialogOpen}
        threatModelId={threatModelId}
        componentThreats={componentThreats}
        scoringMethod={riskScoringMethod}
        activeScoringMethod={activeScoringMethod}
      />

      <AlertDialog open={deleteRiskId !== null} onOpenChange={(open) => !open && setDeleteRiskId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Risk</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete this risk and unlink all associated threats. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} disabled={deleteRisk.isPending}>
              {deleteRisk.isPending ? 'Deleting...' : 'Delete'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
