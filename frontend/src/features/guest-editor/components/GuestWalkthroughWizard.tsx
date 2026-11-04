import { useEffect, useMemo, useState } from 'react'
import { CheckCircle2, AlertTriangle, XCircle, Download, Sparkles, ArrowRight, ArrowLeft } from 'lucide-react'
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
import { Badge } from '@/components/ui/badge'
import {
  ARCHITECTURE_PATTERNS,
  NIST_800_60_INFO_TYPES,
  buildWalkthroughGuestState,
  computeFips199HighWaterMark,
  evaluateControlBaseline,
  type FipsImpact,
  type SelectedInfoTypeImpact,
  type WalkthroughConfig,
} from '../lib/walkthrough'
import type { DeserializedFile } from '../lib/cyclonedx-guest'

const WALKTHROUGH_CACHE_NAME = 'precogly.guest.walkthrough.v1'

interface GuestWalkthroughWizardProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onApplyToCanvas: (loaded: DeserializedFile) => void
}

function downloadBlob(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export function GuestWalkthroughWizard({
  open,
  onOpenChange,
  onApplyToCanvas,
}: GuestWalkthroughWizardProps) {
  const [step, setStep] = useState<1 | 2 | 3>(1)
  const [systemName, setSystemName] = useState('Federal System Prototype')
  const [systemDescription, setSystemDescription] = useState('')
  const [infoTypes, setInfoTypes] = useState<SelectedInfoTypeImpact[]>([
    {
      id: 'C.2.8.1',
      confidentiality: 'moderate',
      integrity: 'moderate',
      availability: 'low',
    },
  ])
  const [patternIds, setPatternIds] = useState<string[]>(['cloudgov-paas'])
  const [selectedThreatIds, setSelectedThreatIds] = useState<string[]>([])

  useEffect(() => {
    try {
      const raw = localStorage.getItem(WALKTHROUGH_CACHE_NAME)
      if (!raw) return
      const saved = JSON.parse(raw) as Partial<WalkthroughConfig>
      if (saved.systemName) setSystemName(saved.systemName)
      if (saved.systemDescription !== undefined) setSystemDescription(saved.systemDescription)
      if (Array.isArray(saved.infoTypes) && saved.infoTypes.length > 0) setInfoTypes(saved.infoTypes)
      if (Array.isArray(saved.patternIds) && saved.patternIds.length > 0) setPatternIds(saved.patternIds)
      if (Array.isArray(saved.selectedThreatIds)) setSelectedThreatIds(saved.selectedThreatIds)
    } catch {
      // Ignore invalid localStorage state
    }
  }, [])

  useEffect(() => {
    try {
      const payload: WalkthroughConfig = {
        systemName,
        systemDescription,
        infoTypes,
        patternIds,
        selectedThreatIds,
      }
      localStorage.setItem(WALKTHROUGH_CACHE_NAME, JSON.stringify(payload))
    } catch {
      // Ignore storage quota errors
    }
  }, [systemName, systemDescription, infoTypes, patternIds, selectedThreatIds])

  const fips = useMemo(() => computeFips199HighWaterMark(infoTypes), [infoTypes])
  const evaluatedControls = useMemo(
    () => evaluateControlBaseline(fips.overall, patternIds),
    [fips.overall, patternIds]
  )
  const candidateThreats = useMemo(
    () =>
      ARCHITECTURE_PATTERNS.filter((p) => patternIds.includes(p.id)).flatMap(
        (p) => p.candidateThreats
      ),
    [patternIds]
  )

  const toggleInfoType = (id: string) => {
    const exists = infoTypes.find((t) => t.id === id)
    if (exists) {
      setInfoTypes(infoTypes.filter((t) => t.id !== id))
      return
    }
    const spec = NIST_800_60_INFO_TYPES.find((t) => t.id === id)
    if (!spec) return
    setInfoTypes([
      ...infoTypes,
      {
        id: spec.id,
        confidentiality: spec.defaultConfidentiality,
        integrity: spec.defaultIntegrity,
        availability: spec.defaultAvailability,
      },
    ])
  }

  const updateImpact = (
    id: string,
    field: 'confidentiality' | 'integrity' | 'availability',
    value: FipsImpact
  ) => {
    setInfoTypes(
      infoTypes.map((item) => (item.id === id ? { ...item, [field]: value } : item))
    )
  }

  const togglePattern = (id: string) => {
    if (patternIds.includes(id)) {
      setPatternIds(patternIds.filter((p) => p !== id))
    } else {
      setPatternIds([...patternIds, id])
    }
  }

  const toggleThreat = (id: string) => {
    if (selectedThreatIds.includes(id)) {
      setSelectedThreatIds(selectedThreatIds.filter((t) => t !== id))
    } else if (selectedThreatIds.length < 5) {
      setSelectedThreatIds([...selectedThreatIds, id])
    }
  }

  const slugName =
    systemName
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9-_]+/g, '-') || 'guided-system'

  const handleApplyAndClose = () => {
    const { deserialized } = buildWalkthroughGuestState({
      systemName,
      systemDescription,
      infoTypes,
      patternIds,
      selectedThreatIds,
    })
    onApplyToCanvas(deserialized)
    onOpenChange(false)
  }

  const handleDownloadJson = () => {
    const { json } = buildWalkthroughGuestState({
      systemName,
      systemDescription,
      infoTypes,
      patternIds,
      selectedThreatIds,
    })
    downloadBlob(`${slugName}.cdx.json`, json, 'application/json')
  }

  const handleDownloadYaml = () => {
    const { yaml } = buildWalkthroughGuestState({
      systemName,
      systemDescription,
      infoTypes,
      patternIds,
      selectedThreatIds,
    })
    downloadBlob(`${slugName}.cdx.yaml`, yaml, 'application/x-yaml')
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl max-h-[88vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-teal-600" />
            Guided System Walkthrough (Step {step} of 3)
          </DialogTitle>
          <DialogDescription>
            Scope FIPS 199 categorization, select platform architecture packs, and generate a
            CycloneDX 2.0 TM-BOM threat model with NIST SP 800-53 Rev. 5 baseline coverage.
          </DialogDescription>
        </DialogHeader>

        {step === 1 && (
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="walkthrough-sys-name">System Name</Label>
                <Input
                  id="walkthrough-sys-name"
                  value={systemName}
                  onChange={(e) => setSystemName(e.target.value)}
                  placeholder="e.g., Federal Procurement Data Feed"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="walkthrough-sys-desc">Brief Description</Label>
                <Input
                  id="walkthrough-sys-desc"
                  value={systemDescription}
                  onChange={(e) => setSystemDescription(e.target.value)}
                  placeholder="Optional mission or boundary summary"
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label>NIST SP 800-60 Vol. II Information Types</Label>
              <div className="divide-y rounded-md border">
                {NIST_800_60_INFO_TYPES.map((info) => {
                  const selected = infoTypes.find((t) => t.id === info.id)
                  return (
                    <div key={info.id} className="p-3 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <label className="flex items-center gap-2 text-sm font-medium cursor-pointer">
                          <input
                            type="checkbox"
                            checked={!!selected}
                            onChange={() => toggleInfoType(info.id)}
                            aria-label={`Select ${info.name}`}
                          />
                          <span>
                            {info.code} — {info.name}
                          </span>
                          <Badge variant="outline" className="text-xs">
                            {info.category}
                          </Badge>
                        </label>
                      </div>
                      {selected && (
                        <div className="grid grid-cols-3 gap-2 pl-6 text-xs">
                          {(['confidentiality', 'integrity', 'availability'] as const).map(
                            (cia) => (
                              <div key={cia} className="flex items-center gap-1.5">
                                <span className="capitalize text-muted-foreground">{cia}:</span>
                                <select
                                  aria-label={`${info.code} ${cia}`}
                                  className="rounded border bg-background px-1.5 py-0.5 text-xs uppercase"
                                  value={selected[cia]}
                                  onChange={(e) =>
                                    updateImpact(info.id, cia, e.target.value as FipsImpact)
                                  }
                                >
                                  <option value="low">Low</option>
                                  <option value="moderate">Moderate</option>
                                  <option value="high">High</option>
                                </select>
                              </div>
                            )
                          )}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>

            <div className="rounded-md border bg-muted/40 p-3 flex items-center justify-between">
              <div className="text-sm">
                <span className="font-semibold">FIPS 199 High-Water-Mark Determination:</span>{' '}
                <span className="text-muted-foreground">
                  C={fips.confidentiality.toUpperCase()} / I={fips.integrity.toUpperCase()} / A=
                  {fips.availability.toUpperCase()}
                </span>
              </div>
              <Badge className="uppercase">{fips.overall} Baseline</Badge>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Select one or more platform architecture patterns. Components, trust zones, and
              inherited controls from each pack will populate your DFD canvas.
            </p>
            <div className="grid gap-2.5 sm:grid-cols-2">
              {ARCHITECTURE_PATTERNS.map((pattern) => {
                const active = patternIds.includes(pattern.id)
                return (
                  <button
                    key={pattern.id}
                    type="button"
                    onClick={() => togglePattern(pattern.id)}
                    className={`text-left rounded-md border p-3 transition-colors ${
                      active
                        ? 'border-primary bg-primary/5 ring-1 ring-primary'
                        : 'hover:bg-muted/50'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium text-sm">{pattern.label}</span>
                      <Badge variant="outline" className="text-xs">
                        {pattern.packSlug}
                      </Badge>
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">{pattern.description}</p>
                    <p className="mt-2 text-xs font-mono text-muted-foreground">
                      {pattern.components.length} component(s) · {pattern.inheritedControls.length}{' '}
                      inherited control(s)
                    </p>
                  </button>
                )
              })}
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">
                NIST SP 800-53 Rev. 5 ({fips.overall.toUpperCase()}) Control Overlay
              </span>
              <div className="flex items-center gap-3 text-xs">
                <span className="flex items-center gap-1 text-green-700">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Inherited (
                  {evaluatedControls.filter((c) => c.state === 'inherited').length})
                </span>
                <span className="flex items-center gap-1 text-amber-700">
                  <AlertTriangle className="h-3.5 w-3.5" /> Shared / CRM (
                  {evaluatedControls.filter((c) => c.state === 'shared').length})
                </span>
                <span className="flex items-center gap-1 text-red-700">
                  <XCircle className="h-3.5 w-3.5" /> Gap (
                  {evaluatedControls.filter((c) => c.state === 'gap').length})
                </span>
              </div>
            </div>

            <div className="max-h-52 overflow-y-auto divide-y rounded-md border text-xs">
              {evaluatedControls.map((ctrl) => (
                <div key={ctrl.id} className="p-2.5 flex items-start gap-2.5">
                  {ctrl.state === 'inherited' && (
                    <CheckCircle2 className="h-4 w-4 text-green-600 shrink-0 mt-0.5" />
                  )}
                  {ctrl.state === 'shared' && (
                    <AlertTriangle className="h-4 w-4 text-amber-600 shrink-0 mt-0.5" />
                  )}
                  {ctrl.state === 'gap' && (
                    <XCircle className="h-4 w-4 text-red-600 shrink-0 mt-0.5" />
                  )}
                  <div className="space-y-0.5">
                    <div className="font-medium">
                      {ctrl.id} — {ctrl.name}
                    </div>
                    <div className="text-muted-foreground">{ctrl.guidance}</div>
                  </div>
                </div>
              ))}
            </div>

            {candidateThreats.length > 0 && (
              <div className="space-y-2">
                <Label className="text-xs">
                  Optional Risk Enrichment (select up to 5 pack threat scenarios)
                </Label>
                <div className="divide-y rounded-md border text-xs">
                  {candidateThreats.map((cand) => (
                    <label
                      key={cand.id}
                      className="flex items-start gap-2 p-2 cursor-pointer hover:bg-muted/40"
                    >
                      <input
                        type="checkbox"
                        checked={selectedThreatIds.includes(cand.id)}
                        onChange={() => toggleThreat(cand.id)}
                      />
                      <div>
                        <span className="font-medium">{cand.name}</span>{' '}
                        <Badge variant="outline" className="text-[10px]">
                          {cand.controlId}
                        </Badge>
                        <p className="text-muted-foreground">{cand.description}</p>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        <DialogFooter className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            {step > 1 && (
              <Button variant="outline" size="sm" onClick={() => setStep((step - 1) as 1 | 2)}>
                <ArrowLeft className="h-4 w-4 mr-1" />
                Back
              </Button>
            )}
          </div>
          <div className="flex items-center gap-2">
            {step < 3 ? (
              <Button size="sm" onClick={() => setStep((step + 1) as 2 | 3)}>
                Next
                <ArrowRight className="h-4 w-4 ml-1" />
              </Button>
            ) : (
              <>
                <Button variant="outline" size="sm" onClick={handleDownloadJson}>
                  <Download className="h-4 w-4 mr-1.5" />
                  Export CDX JSON
                </Button>
                <Button variant="outline" size="sm" onClick={handleDownloadYaml}>
                  <Download className="h-4 w-4 mr-1.5" />
                  Export CDX YAML
                </Button>
                <Button size="sm" onClick={handleApplyAndClose}>
                  Populate Canvas
                </Button>
              </>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
