import { useEffect, useState } from 'react'
import { Plus, Search, FileText, Library, Info, Loader2 } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { SEVERITY_COLORS } from './severity-utils'
import { OwlMark } from '@/features/ai/components/OwlMark'
import { OwlToggle } from '@/features/ai/components/OwlToggle'
import { AiErrorState } from '@/features/ai/components/AiErrorState'
import { useAiAvailability, useSuggestThreats, type ThreatSuggestion } from '@/features/ai/api/suggest'
import {
  useThreatLibrary,
  useComponentThreats,
  useFlowThreats,
  useCreateComponentThreat,
  useCreateFlowThreat,
  useCreateInstanceTaxonomyEntry,
} from '@/features/threat-models/api/threats'
import { useTaxonomyEntries } from '@/features/libraries/api/libraries'
import { TRIAGE_STATUSES, type TriageStatus } from '@/types/triage'
import { formatTaxonomyEntryLabel } from '@/types/domain'

const SEVERITY_OPTIONS = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
]

interface AddThreatDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  targetId: number // Component ID or DataFlow ID
  targetType: 'component' | 'dataflow'
  targetName: string
  threatModelId?: string
  onSuccess?: () => void
}

export function AddThreatDialog({
  open,
  onOpenChange,
  targetId,
  targetType,
  targetName,
  threatModelId,
  onSuccess,
}: AddThreatDialogProps) {
  const [activeTab, setActiveTab] = useState<'library' | 'custom'>('library')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedThreatId, setSelectedThreatId] = useState<number | null>(null)
  const [selectedSeverity, setSelectedSeverity] = useState('medium')

  // Custom threat fields
  const [customName, setCustomName] = useState('')
  const [customDescription, setCustomDescription] = useState('')
  const [customSeverity, setCustomSeverity] = useState('medium')
  const [customTriageStatus, setCustomTriageStatus] = useState<TriageStatus>('open')
  const [customTaxonomyEntryId, setCustomTaxonomyEntryId] = useState<string>('none')
  const [showAllThreats, setShowAllThreats] = useState(false)
  // Whether the list is the model's ranking rather than the raw library. This
  // is a third state layered on the scope toggle rather than a fourth cell in a
  // matrix: `candidate_library_threats` only ever ranks the component's own
  // pool, so ranking and "show all" are mutually exclusive by construction.
  const [showRanked, setShowRanked] = useState(false)

  // Ranked stays component-scoped so the pool on screen is the one the model
  // was given; only "show all" drops the component filter.
  const effectiveComponentId = (targetType === 'component' && !showAllThreats)
    ? targetId
    : undefined

  const { data: threatLibrary, isLoading } = useThreatLibrary(effectiveComponentId, threatModelId)
  const createComponentThreat = useCreateComponentThreat()
  const createFlowThreat = useCreateFlowThreat()
  const createInstanceTaxonomyEntry = useCreateInstanceTaxonomyEntry()
  const { data: allTaxonomyEntries } = useTaxonomyEntries()

  const taxonomyEntriesByTaxonomy = allTaxonomyEntries
    ? Object.entries(
        allTaxonomyEntries.reduce<Record<string, typeof allTaxonomyEntries>>((acc, entry) => {
          const key = entry.taxonomyName ?? entry.taxonomySlug
          if (!acc[key]) acc[key] = []
          acc[key].push(entry)
          return acc
        }, {})
      )
    : []

  // Ranking is component-only: the suggest endpoint takes a component id and
  // has no dataflow equivalent, so dataflows never see the option at all.
  const aiComponentId = targetType === 'component' ? targetId : null
  const availability = useAiAvailability(aiComponentId)
  const aiAvailable = availability.data?.available ?? false
  const suggest = useSuggestThreats()

  // Threats the target already carries. Offering one again is a dead end — the
  // backend rejects the duplicate — so they come out of the list entirely
  // rather than sitting there waiting to fail.
  //
  // Triaged threats count as present, matching what the ranker does
  // (`candidate_library_threats` excludes every instance, triaged or not).
  // A triage decision shows up in compliance reporting,
  // so the way back is to change the triage status, not a silent re-add.
  const componentThreats = useComponentThreats(aiComponentId)
  const flowThreats = useFlowThreats(targetType === 'dataflow' ? targetId : null)
  const alreadyAdded = new Set(
    (targetType === 'component'
      ? componentThreats.data?.map((t) => t.threatLibrary)
      : flowThreats.data?.map((t) => t.threatLibrary)
    )?.filter((id): id is number => id !== null) ?? []
  )

  const matchesQuery = (name?: string | null, description?: string | null, taxonomy?: string[]) => {
    const query = searchQuery.toLowerCase()
    return (
      name?.toLowerCase().includes(query) ||
      description?.toLowerCase().includes(query) ||
      (taxonomy?.some((t) => t.toLowerCase().includes(query)) ?? false)
    )
  }

  const availableThreats = threatLibrary?.filter((threat) => !alreadyAdded.has(threat.id)) ?? []

  const filteredThreats = availableThreats.filter((threat) => {
    const query = searchQuery.toLowerCase()
    const taxonomyMatch = threat.taxonomyEntries?.some(
      (entry) => entry.title.toLowerCase().includes(query) || entry.externalId.toLowerCase().includes(query)
    ) ?? false
    return (
      threat.name?.toLowerCase().includes(query) ||
      threat.description?.toLowerCase().includes(query) ||
      taxonomyMatch
    )
  })

  const filteredSuggestions = suggest.data?.suggestions.filter((s) =>
    matchesQuery(s.threatName, s.threatDescription, s.taxonomy)
  ) ?? []

  // The confirmation panel needs the selected threat's name whichever list
  // produced it; only the name differs between the two shapes.
  const selectedThreatName = showRanked
    ? suggest.data?.suggestions.find((s) => s.threatLibrary === selectedThreatId)?.threatName
    : threatLibrary?.find((t) => t.id === selectedThreatId)?.name

  // Both controls invalidate the selection — the same row may not exist in the
  // next list, and a stale id would submit something the user can't see.
  const handleShowAllChange = (next: boolean) => {
    setShowAllThreats(next)
    setSelectedThreatId(null)
    // Widening the scope leaves ranking with no pool it can describe, so it
    // switches off rather than sitting stale over a list it didn't rank.
    if (next) setShowRanked(false)
  }

  const handleRankedChange = (next: boolean) => {
    setShowRanked(next)
    setSelectedThreatId(null)
    // Spend an LLM call only on entering ranked mode, and only once per open —
    // re-entering reuses the ranking already fetched.
    if (next && aiComponentId !== null && !suggest.data && !suggest.isPending) {
      suggest.mutate(aiComponentId)
    }
  }

  const handleAddFromLibrary = () => {
    if (!selectedThreatId) return

    const onMutationSuccess = () => {
      onOpenChange(false)
      resetForm()
      onSuccess?.()
    }

    if (targetType === 'component') {
      createComponentThreat.mutate(
        { component: targetId, threatLibrary: selectedThreatId, inherentSeverity: selectedSeverity },
        { onSuccess: onMutationSuccess }
      )
    } else {
      createFlowThreat.mutate(
        { dataFlow: targetId, threatLibrary: selectedThreatId, inherentSeverity: selectedSeverity },
        { onSuccess: onMutationSuccess }
      )
    }
  }

  const handleAddCustom = () => {
    if (!customName.trim()) return

    const baseData = {
      threatLibrary: null as null,
      threatName: customName,
      threatDescription: customDescription,
      inherentSeverity: customSeverity,
      triageStatus: customTriageStatus,
      status: 'exposed',
    }
    const taxonomyEntryIdNum = customTaxonomyEntryId !== 'none' ? Number(customTaxonomyEntryId) : null
    const onMutationSuccess = (result: unknown) => {
      const { id } = result as { id: number }
      if (taxonomyEntryIdNum) {
        const linkPayload = targetType === 'component'
          ? { taxonomyEntry: taxonomyEntryIdNum, componentThreat: id }
          : { taxonomyEntry: taxonomyEntryIdNum, flowThreat: id }
        createInstanceTaxonomyEntry.mutate(linkPayload)
      }
      onOpenChange(false)
      resetForm()
      onSuccess?.()
    }

    if (targetType === 'component') {
      createComponentThreat.mutate(
        { component: targetId, ...baseData },
        { onSuccess: onMutationSuccess }
      )
    } else {
      createFlowThreat.mutate(
        { dataFlow: targetId, ...baseData },
        { onSuccess: onMutationSuccess }
      )
    }
  }

  const resetForm = () => {
    setSearchQuery('')
    setSelectedThreatId(null)
    setSelectedSeverity('medium')
    setCustomName('')
    setCustomDescription('')
    setCustomSeverity('medium')
    setCustomTriageStatus('open')
    setCustomTaxonomyEntryId('none')
    setActiveTab('library')
    setShowAllThreats(false)
    setShowRanked(false)
    // Drop the ranking too, so reopening on another component never shows the
    // previous component's suggestions while its own request is in flight.
    suggest.reset()
  }

  // Closing the dialog does not unmount it — both call sites re-render it in
  // place with a new `targetId` — so without this every field survives a Cancel
  // and reappears against whatever component is opened next. For the ranking
  // that is not merely untidy: the suggestions stay on screen labelled "Ranked
  // for this component", the `!suggest.data` guard suppresses the refetch that
  // would correct them, and accepting one files another component's threat here.
  //
  // Resetting on open rather than on close keeps the fields populated through
  // the closing animation instead of blanking them mid-fade. The cost is that
  // reopening the same component re-ranks, spending a second metered call on a
  // result we had — worth it to never show a ranking that isn't this
  // component's.
  useEffect(() => {
    if (open) resetForm()
    // `resetForm` is redeclared every render; `open` is the real trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const isSubmitting = createComponentThreat.isPending || createFlowThreat.isPending

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Add Threat</DialogTitle>
          <DialogDescription>
            Add a threat to <span className="font-medium">{targetName}</span>
          </DialogDescription>
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as 'library' | 'custom')}>
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="library">From Library</TabsTrigger>
            <TabsTrigger value="custom">Custom Threat</TabsTrigger>
          </TabsList>

          <TabsContent value="library" className="space-y-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search threats..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>

            {targetType === 'component' && (
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-sm text-muted-foreground min-w-0">
                  {showRanked ? <OwlMark className="h-4 w-4 shrink-0" /> : <Library className="h-4 w-4 shrink-0" />}
                  <span className="truncate">
                    {showRanked
                      ? 'Ranked for this component'
                      : showAllThreats
                        ? 'Showing all threats'
                        : "Showing threats for this component's library"}
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <OwlToggle
                    label="Rank"
                    tooltip={showRanked ? 'Show the unranked library' : 'Rank these threats by relevance'}
                    active={showRanked}
                    pending={suggest.isPending}
                    unavailable={!aiAvailable}
                    blockedReason={
                      showAllThreats ? 'Ranking covers this component’s library only' : null
                    }
                    onChange={handleRankedChange}
                  />
                  <Switch
                    id="show-all-threats"
                    checked={showAllThreats}
                    onCheckedChange={handleShowAllChange}
                  />
                  <Label htmlFor="show-all-threats" className="text-sm">
                    Show all
                  </Label>
                </div>
              </div>
            )}

            <ScrollArea className="h-[300px] border rounded-md">
              {showRanked ? (
                <RankedList
                  pending={suggest.isPending}
                  error={suggest.error}
                  suggestions={filteredSuggestions}
                  hasResults={suggest.data !== undefined}
                  hasExistingThreats={alreadyAdded.size > 0}
                  searchQuery={searchQuery}
                  selectedThreatId={selectedThreatId}
                  onSelect={(suggestion) => {
                    setSelectedThreatId(suggestion.threatLibrary)
                    // Carry the model's severity through as the default so the
                    // rationale the user just read matches what gets saved.
                    setSelectedSeverity(suggestion.suggestedSeverity)
                  }}
                  onRetry={() => aiComponentId !== null && suggest.mutate(aiComponentId)}
                />
              ) : isLoading ? (
                <div className="p-4 text-center text-muted-foreground">Loading threats...</div>
              ) : filteredThreats.length === 0 ? (
                <div className="p-4 text-center text-muted-foreground">
                  {searchQuery
                    ? 'No threats match your search'
                    : threatLibrary && threatLibrary.length > 0
                      // Distinguishing these two matters: "already added" means the
                      // work is done, "none available" means look somewhere else.
                      ? `Every applicable threat is already on ${targetName}.`
                      : 'No threats available in library'}
                </div>
              ) : (
                <div className="p-2 space-y-1">
                  {filteredThreats.map((threat) => (
                    <button
                      key={threat.id}
                      onClick={() => setSelectedThreatId(threat.id)}
                      className={cn(
                        'w-full text-left p-3 rounded-md transition-colors',
                        selectedThreatId === threat.id
                          ? 'bg-primary/10 border border-primary'
                          : 'hover:bg-muted'
                      )}
                    >
                      <div className="flex items-center gap-1.5">
                        <span className="font-medium">{threat.name}</span>
                        {(threat.description || (threat.taxonomyEntries && threat.taxonomyEntries.length > 0)) && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Info className="h-3.5 w-3.5 text-muted-foreground shrink-0 cursor-help" />
                            </TooltipTrigger>
                            <TooltipContent side="right" className="max-w-xs">
                              {threat.description && (
                                <p>{threat.description}</p>
                              )}
                              {threat.taxonomyEntries && threat.taxonomyEntries.length > 0 && (
                                <p className="mt-1 opacity-75">
                                  {threat.taxonomyEntries.map((e) => e.title).join(' · ')}
                                </p>
                              )}
                            </TooltipContent>
                          </Tooltip>
                        )}
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </ScrollArea>

            {selectedThreatName && (
              <div className="space-y-3 p-3 bg-muted/50 rounded-md">
                <div>
                  <Label className="text-xs text-muted-foreground">Selected Threat</Label>
                  <p className="font-medium">{selectedThreatName}</p>
                </div>
                <div className="flex gap-4">
                  <div className="flex-1">
                    <Label htmlFor="library-severity">Severity</Label>
                    <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
                      <SelectTrigger id="library-severity">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SEVERITY_OPTIONS.map((opt) => (
                          <SelectItem key={opt.value} value={opt.value}>
                            {opt.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </div>
            )}
          </TabsContent>

          <TabsContent value="custom" className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="custom-name">Threat Name *</Label>
              <Input
                id="custom-name"
                placeholder="Enter threat name..."
                value={customName}
                onChange={(e) => setCustomName(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="custom-description">Description</Label>
              <Textarea
                id="custom-description"
                placeholder="Describe the threat..."
                value={customDescription}
                onChange={(e) => setCustomDescription(e.target.value)}
                rows={3}
              />
            </div>

            <div className="flex gap-4">
              <div className="flex-1 space-y-2">
                <Label htmlFor="custom-severity">Severity *</Label>
                <Select value={customSeverity} onValueChange={setCustomSeverity}>
                  <SelectTrigger id="custom-severity">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITY_OPTIONS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="flex-1 space-y-2">
                <Label htmlFor="custom-triage-status">Status</Label>
                <Select value={customTriageStatus} onValueChange={(v) => setCustomTriageStatus(v as TriageStatus)}>
                  <SelectTrigger id="custom-triage-status">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TRIAGE_STATUSES.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {taxonomyEntriesByTaxonomy.length > 0 && (
              <div className="space-y-2">
                <Label htmlFor="custom-taxonomy">Taxonomy Category</Label>
                <Select value={customTaxonomyEntryId} onValueChange={setCustomTaxonomyEntryId}>
                  <SelectTrigger id="custom-taxonomy">
                    <SelectValue placeholder="None" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">None</SelectItem>
                    {taxonomyEntriesByTaxonomy.map(([taxonomyName, entries]) => (
                      entries.map((entry) => (
                        <SelectItem key={entry.id} value={String(entry.id)}>
                          {taxonomyEntriesByTaxonomy.length > 1
                            ? `${taxonomyName}: ${formatTaxonomyEntryLabel(entry)}`
                            : formatTaxonomyEntryLabel(entry)}
                        </SelectItem>
                      ))
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            <div className="flex items-center gap-2 p-3 bg-muted/50 rounded-md text-sm text-muted-foreground">
              <FileText className="h-4 w-4 shrink-0" />
              <p>Custom threats are not linked to the threat library and won't auto-generate countermeasures.</p>
            </div>
          </TabsContent>
        </Tabs>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          {activeTab === 'library' ? (
            <Button
              onClick={handleAddFromLibrary}
              disabled={!selectedThreatId || isSubmitting}
            >
              <Plus className="h-4 w-4 mr-2" />
              Add Threat
            </Button>
          ) : (
            <Button
              onClick={handleAddCustom}
              disabled={!customName.trim() || isSubmitting}
            >
              <Plus className="h-4 w-4 mr-2" />
              Add Custom Threat
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/**
 * The ranked view of the same list: each row keeps the model's reasoning and
 * suggested severity next to the threat, so the user reviews a judgement rather
 * than an unexplained reordering.
 *
 * The pool here is narrower than the plain library list by design — the backend
 * excludes threats already on the component ("suggest gaps, not duplicates"), so
 * the counts legitimately differ between the two views.
 */
function RankedList({
  pending,
  error,
  suggestions,
  hasResults,
  hasExistingThreats,
  searchQuery,
  selectedThreatId,
  onSelect,
  onRetry,
}: {
  pending: boolean
  error: unknown
  suggestions: ThreatSuggestion[]
  hasResults: boolean
  /** Whether the target already carries any threats — see the empty state below. */
  hasExistingThreats: boolean
  searchQuery: string
  selectedThreatId: number | null
  onSelect: (suggestion: ThreatSuggestion) => void
  onRetry: () => void
}) {
  if (pending) {
    return (
      <div className="flex items-center justify-center gap-2 p-4 py-12 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Ranking relevant threats…
      </div>
    )
  }

  if (error) {
    return (
      <AiErrorState
        error={error}
        fallbackMessage="Something went wrong ranking these threats."
        onRetry={onRetry}
      />
    )
  }

  if (!hasResults) return null

  if (suggestions.length === 0) {
    // An empty ranking has two very different causes, and guessing wrong tells
    // the user something untrue. If the component already carries threats, the
    // pool really is exhausted. If it carries none, there was nothing to rank
    // in the first place — a component with no library link grounds nothing,
    // which is the usual reason — so say that instead of claiming the work is
    // already done.
    return (
      <div className="p-4 py-10 text-center text-sm text-muted-foreground">
        {searchQuery
          ? 'No ranked threats match your search'
          : hasExistingThreats
            ? 'Nothing left to suggest — every applicable threat is already on this component.'
            : 'No suggestions for this component. It isn’t linked to a component library, so there’s nothing to ground suggestions in.'}
      </div>
    )
  }

  return (
    <div className="p-2 space-y-1">
      {suggestions.map((suggestion) => (
        <button
          key={suggestion.threatLibrary}
          onClick={() => onSelect(suggestion)}
          className={cn(
            'w-full text-left p-3 rounded-md transition-colors',
            selectedThreatId === suggestion.threatLibrary
              ? 'bg-primary/10 border border-primary'
              : 'hover:bg-muted'
          )}
        >
          <div className="flex items-center gap-1.5">
            <span className="font-medium">{suggestion.threatName}</span>
            <Badge
              variant="outline"
              className={cn('shrink-0 text-[10px]', SEVERITY_COLORS[suggestion.suggestedSeverity])}
            >
              {suggestion.suggestedSeverity}
            </Badge>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">{suggestion.rationale}</p>
          {suggestion.source.packName && (
            <p className="mt-1 text-[11px] text-muted-foreground/75">
              from {suggestion.source.packName}
            </p>
          )}
        </button>
      ))}
    </div>
  )
}
