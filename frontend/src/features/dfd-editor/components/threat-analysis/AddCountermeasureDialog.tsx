import { useState, useMemo } from 'react'
import { Plus, Search, FileText, Link2 } from 'lucide-react'
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
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn } from '@/lib/utils'
import {
  useCountermeasureLibrary,
  useCountermeasuresInUse,
  useCreateCountermeasure,
  useApplyCountermeasure,
} from '@/features/threat-models/api/threats'
import { Checkbox } from '@/components/ui/checkbox'
import { COUNTERMEASURE_STATUS_CONFIG } from '@/features/dfd-editor/types/threat-analysis'
import type { CountermeasureStatus } from '@/features/dfd-editor/types/threat-analysis'
import { CONTROL_FUNCTIONS, CONTROL_NATURES } from '@/types/controls'

interface AddCountermeasureDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatId: number // Backend threat instance ID
  threatType: 'component' | 'dataflow'
  threatName: string
  threatLibraryId?: number | null // For filtering applicable countermeasures
  threatModelId?: string
  onSuccess?: () => void
}

export function AddCountermeasureDialog({
  open,
  onOpenChange,
  threatId,
  threatType,
  threatName,
  threatLibraryId,
  threatModelId,
  onSuccess,
}: AddCountermeasureDialogProps) {
  const [activeTab, setActiveTab] = useState<'in-use' | 'library' | 'custom'>('in-use')
  const [searchQuery, setSearchQuery] = useState('')
  const [inUseSearchQuery, setInUseSearchQuery] = useState('')
  const [selectedCountermeasureId, setSelectedCountermeasureId] = useState<number | null>(null)

  // Custom countermeasure fields
  const [customName, setCustomName] = useState('')
  const [customDescription, setCustomDescription] = useState('')
  const [customControlFunctions, setCustomControlFunctions] = useState<string[]>([])
  const [customControlNature, setCustomControlNature] = useState('')

  // Fetch countermeasures - filter by applicable threats if we have a library threat
  const { data: countermeasureLibrary, isLoading } = useCountermeasureLibrary(threatLibraryId, threatModelId)
  const { data: inUseData, isLoading: isLoadingInUse } = useCountermeasuresInUse(threatModelId)
  const createCountermeasure = useCreateCountermeasure()
  const applyCountermeasure = useApplyCountermeasure()

  // Filter out countermeasures already linked to the current threat
  const availableInUseCountermeasures = useMemo(() => {
    if (!inUseData?.countermeasures) return []
    return inUseData.countermeasures.filter((cm) => {
      // Filter out already-linked
      const isAlreadyLinked = cm.linkedThreats.some((lt) => lt.threatId === threatId)
      if (isAlreadyLinked) return false
      // Apply search filter
      if (inUseSearchQuery) {
        const query = inUseSearchQuery.toLowerCase()
        return cm.countermeasureName.toLowerCase().includes(query)
      }
      return true
    })
  }, [inUseData, threatId, inUseSearchQuery])

  const filteredCountermeasures = countermeasureLibrary?.filter((cm) => {
    const query = searchQuery.toLowerCase()
    return (
      cm.name.toLowerCase().includes(query) ||
      (cm.description?.toLowerCase().includes(query) ?? false) ||
      (cm.controlFunctions?.join(' ').toLowerCase().includes(query) ?? false)
    )
  }) ?? []

  const selectedCountermeasure = countermeasureLibrary?.find((cm) => cm.id === selectedCountermeasureId)

  const handleLinkExisting = (countermeasureId: number) => {
    const onMutationSuccess = () => {
      onOpenChange(false)
      resetForm()
      onSuccess?.()
    }
    applyCountermeasure.mutate(
      { threatId, threatType, existingCountermeasureId: countermeasureId },
      { onSuccess: onMutationSuccess }
    )
  }

  const handleAddFromLibrary = () => {
    if (!selectedCountermeasureId) return

    const countermeasureDefaultStatus = selectedCountermeasure?.defaultStatus ?? 'gap'
    const onMutationSuccess = () => {
      onOpenChange(false)
      resetForm()
      onSuccess?.()
    }

    createCountermeasure.mutate(
      { threatModel: threatModelId!, threatId, threatType, countermeasureLibrary: selectedCountermeasureId, status: countermeasureDefaultStatus },
      { onSuccess: onMutationSuccess }
    )
  }

  const handleAddCustom = () => {
    if (!customName.trim()) return

    const onMutationSuccess = () => {
      onOpenChange(false)
      resetForm()
      onSuccess?.()
    }

    createCountermeasure.mutate(
      {
        threatModel: threatModelId!,
        threatId,
        threatType,
        countermeasureLibrary: null as null,
        countermeasureName: customName,
        countermeasureDescription: customDescription,
        controlFunctions: customControlFunctions.length > 0 ? customControlFunctions : undefined,
        controlNature: customControlNature || undefined,
        status: 'gap',
      },
      { onSuccess: onMutationSuccess }
    )
  }

  const resetForm = () => {
    setSearchQuery('')
    setInUseSearchQuery('')
    setSelectedCountermeasureId(null)
    setCustomName('')
    setCustomDescription('')
    setCustomControlFunctions([])
    setCustomControlNature('')
    setActiveTab('in-use')
  }

  const isSubmitting = createCountermeasure.isPending || applyCountermeasure.isPending

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl overflow-hidden">
        <DialogHeader>
          <DialogTitle>Add Countermeasure</DialogTitle>
          <DialogDescription>
            Add a countermeasure for threat: <span className="font-medium">{threatName}</span>
          </DialogDescription>
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as 'in-use' | 'library' | 'custom')}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="in-use">In Use</TabsTrigger>
            <TabsTrigger value="library">From Library</TabsTrigger>
            <TabsTrigger value="custom">Custom</TabsTrigger>
          </TabsList>

          <TabsContent value="in-use" className="space-y-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search countermeasures in use..."
                value={inUseSearchQuery}
                onChange={(e) => setInUseSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>

            <p className="text-xs text-muted-foreground">
              Link an existing countermeasure from this threat model to share it across threats.
            </p>

            <ScrollArea className="h-[300px] border rounded-md">
              {isLoadingInUse ? (
                <div className="p-4 text-center text-muted-foreground">Loading countermeasures...</div>
              ) : availableInUseCountermeasures.length === 0 ? (
                <div className="p-4 text-center text-muted-foreground">
                  {inUseSearchQuery
                    ? 'No countermeasures match your search'
                    : 'No other countermeasures available to link'}
                </div>
              ) : (
                <div className="p-2 space-y-1">
                  {availableInUseCountermeasures.map((cm) => {
                    const statusConfig = COUNTERMEASURE_STATUS_CONFIG[cm.status as CountermeasureStatus]
                    return (
                      <div
                        key={cm.id}
                        className="flex items-start justify-between gap-2 p-3 rounded-md hover:bg-muted"
                      >
                        <div className="flex-1 min-w-0">
                          <p className="font-medium truncate">{cm.countermeasureName}</p>
                          <div className="flex items-center gap-2 mt-1">
                            {statusConfig && (
                              <span className="text-xs px-1.5 py-0.5 rounded" style={{ backgroundColor: statusConfig.color + '20', color: statusConfig.color }}>
                                {statusConfig.label}
                              </span>
                            )}
                            {cm.assignedOwnerEmail && (
                              <span className="text-xs text-muted-foreground">{cm.assignedOwnerEmail}</span>
                            )}
                          </div>
                          {cm.linkedThreats.length > 0 && (
                            <div className="text-xs text-muted-foreground mt-1">
                              Applied to: {cm.linkedThreats.map((lt) => lt.threatName || lt.componentName || lt.flowLabel).join(', ')}
                            </div>
                          )}
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleLinkExisting(cm.id)}
                          disabled={isSubmitting}
                        >
                          <Link2 className="h-3.5 w-3.5 mr-1" />
                          Link
                        </Button>
                      </div>
                    )
                  })}
                </div>
              )}
            </ScrollArea>
          </TabsContent>

          <TabsContent value="library" className="space-y-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search countermeasures..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>

            {threatLibraryId != null && !Number.isNaN(threatLibraryId) && (
              <p className="text-xs text-muted-foreground">
                Showing countermeasures applicable to this threat type. Clear search to see all.
              </p>
            )}

            <ScrollArea className="h-[300px] border rounded-md">
              {isLoading ? (
                <div className="p-4 text-center text-muted-foreground">Loading countermeasures...</div>
              ) : filteredCountermeasures.length === 0 ? (
                <div className="p-4 text-center text-muted-foreground">
                  {searchQuery ? 'No countermeasures match your search' : 'No countermeasures available in library'}
                </div>
              ) : (
                <div className="p-2 space-y-1">
                  {filteredCountermeasures.map((cm) => (
                    <button
                      key={cm.id}
                      onClick={() => setSelectedCountermeasureId(cm.id)}
                      className={cn(
                        'w-full text-left p-3 rounded-md transition-colors',
                        selectedCountermeasureId === cm.id
                          ? 'bg-primary/10 border border-primary'
                          : 'hover:bg-muted'
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1 min-w-0">
                          <p className="font-medium truncate">{cm.name}</p>
                          {cm.description && (
                            <p className="text-sm text-muted-foreground line-clamp-2">
                              {cm.description}
                            </p>
                          )}
                        </div>
                        <div className="flex gap-1 shrink-0">
                          {cm.controlFunctions?.map((fn) => (
                            <span key={fn} className="text-xs px-2 py-1 rounded-full bg-muted capitalize">
                              {fn}
                            </span>
                          ))}
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </ScrollArea>

            {selectedCountermeasure && (
              <div className="p-3 bg-muted/50 rounded-md">
                <Label className="text-xs text-muted-foreground">Selected Countermeasure</Label>
                <p className="font-medium">{selectedCountermeasure.name}</p>
                {selectedCountermeasure.controlFunctions?.length > 0 && (
                  <p className="text-sm text-muted-foreground capitalize">
                    Functions: {selectedCountermeasure.controlFunctions.join(', ')}
                  </p>
                )}
                {selectedCountermeasure.controlNature && (
                  <p className="text-sm text-muted-foreground capitalize">
                    Nature: {selectedCountermeasure.controlNature}
                  </p>
                )}
              </div>
            )}
          </TabsContent>

          <TabsContent value="custom" className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="custom-cm-name">Countermeasure Name *</Label>
              <Input
                id="custom-cm-name"
                placeholder="Enter countermeasure name..."
                value={customName}
                onChange={(e) => setCustomName(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="custom-cm-description">Description</Label>
              <Textarea
                id="custom-cm-description"
                placeholder="Describe the countermeasure..."
                value={customDescription}
                onChange={(e) => setCustomDescription(e.target.value)}
                rows={3}
              />
            </div>

            <div className="space-y-2">
              <Label>Control Functions</Label>
              <div className="flex flex-wrap gap-3">
                {CONTROL_FUNCTIONS.map((fn) => (
                  <label key={fn.value} className="flex items-center gap-1.5 text-sm">
                    <Checkbox
                      checked={customControlFunctions.includes(fn.value)}
                      onCheckedChange={(checked) => {
                        setCustomControlFunctions((prev) =>
                          checked
                            ? [...prev, fn.value]
                            : prev.filter((v) => v !== fn.value)
                        )
                      }}
                    />
                    {fn.label}
                  </label>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="custom-cm-control-nature">Control Nature</Label>
              <Select value={customControlNature} onValueChange={setCustomControlNature}>
                <SelectTrigger id="custom-cm-control-nature">
                  <SelectValue placeholder="Select control nature..." />
                </SelectTrigger>
                <SelectContent>
                  {CONTROL_NATURES.map((nature) => (
                    <SelectItem key={nature.value} value={nature.value}>
                      {nature.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-center gap-2 p-3 bg-muted/50 rounded-md text-sm text-muted-foreground">
              <FileText className="h-4 w-4 shrink-0" />
              <p>Custom countermeasures are not linked to the library and won't have compliance mappings by default.</p>
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
              disabled={!selectedCountermeasureId || isSubmitting}
            >
              <Plus className="h-4 w-4 mr-2" />
              Add Countermeasure
            </Button>
          ) : activeTab === 'custom' ? (
            <Button
              onClick={handleAddCustom}
              disabled={!customName.trim() || isSubmitting}
            >
              <Plus className="h-4 w-4 mr-2" />
              Add Custom Countermeasure
            </Button>
          ) : null}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
