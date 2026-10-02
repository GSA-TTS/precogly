/**
 * Read-only threat analysis view for shared/public views.
 * Computes threats from canvas data using the threat registry (same as authenticated view).
 * Displays threats and countermeasures without editing capabilities.
 */

import { useMemo, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  AlertTriangle,
  Shield,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronDown,
  ChevronRight,
  Info,
} from 'lucide-react'
import { type TaxonomyEntry } from '@/types/domain'
import { isActiveThreat } from '@/types/triage'
import { TaxonomyBadges } from '@/components/shared/TaxonomyBadges'
import type { ComponentThreat, ComponentThreatCountermeasure } from '@/features/dfd-editor/types/threat-analysis'
import type { DiagramNode } from '@/features/dfd-editor/types'
import type { ThreatAnalysisData, SharedThreat } from '@/features/organization/types/organization'
import type { DataFlowEdge } from '@/features/dfd-editor/types'

export interface DiagramData {
  id: string | number
  name: string
  canvasData?: {
    nodes?: DiagramNode[]
    edges?: DataFlowEdge[]
  }
}

// Countermeasure status config
const STATUS_CONFIG: Record<string, { label: string; icon: typeof CheckCircle2; color: string }> = {
  platform: { label: 'Platform', icon: CheckCircle2, color: 'text-green-600' },
  verified: { label: 'Verified', icon: CheckCircle2, color: 'text-green-600' },
  planned: { label: 'Planned', icon: Clock, color: 'text-blue-600' },
  gap: { label: 'Gap', icon: XCircle, color: 'text-red-600' },
  waived: { label: 'Waived', icon: Info, color: 'text-gray-600' },
}

interface ReadOnlyThreatAnalysisViewProps {
  diagrams?: DiagramData[]
  threatAnalysisData?: ThreatAnalysisData
  className?: string
}

/**
 * Convert SharedThreat from backend to ComponentThreat format for display.
 * Handles both component threats and flow threats.
 */
function convertSharedThreatToComponentThreat(sharedThreat: SharedThreat): ComponentThreat {
  const timestamp = new Date().toISOString()

  // Use node_id or edge_id as component_id for mapping
  const componentId = sharedThreat.type === 'component'
    ? (sharedThreat.nodeId || `component-${sharedThreat.componentId}`)
    : (sharedThreat.edgeId || `flow-${sharedThreat.flowId}`)

  return {
    id: `shared-threat-${sharedThreat.id}`,
    diagramId: sharedThreat.dfdId || 'unknown',
    sourceDiagramId: sharedThreat.dfdId || 'unknown',
    sourceDiagramTitle: sharedThreat.dfdName || 'Unknown Diagram',
    componentId,
    threatId: sharedThreat.threatLibraryId?.toString() || 'custom',
    triageStatus: (sharedThreat.triageStatus as 'open' | 'accept' | 'mitigate' | 'delegate' | 'eliminate') || 'open',
    createdAt: timestamp,
    updatedAt: timestamp,
    threatName: sharedThreat.threatName || 'Unknown Threat',
    threatDescription: sharedThreat.threatDescription || '',
    taxonomyEntries: sharedThreat.taxonomyEntries as TaxonomyEntry[] | undefined,
    countermeasures: sharedThreat.countermeasures.map((cm): ComponentThreatCountermeasure => ({
      id: `shared-cm-${cm.id}`,
      countermeasureId: cm.countermeasureLibraryId?.toString() || 'custom',
      componentThreatId: `shared-threat-${sharedThreat.id}`,
      status: cm.status,
      createdAt: timestamp,
      updatedAt: timestamp,
      countermeasureName: cm.countermeasureName || 'Unknown Countermeasure',
      countermeasureDescription: cm.countermeasureDescription || '',
      controlFunctions: cm.controlFunctions || [],
      controlNature: cm.controlNature || '',
      owner: cm.assignedOwnerEmail || undefined,
    })),
  }
}

function CountermeasureRow({ cm }: { cm: ComponentThreatCountermeasure }) {
  const cmName = cm.countermeasureName || cm.countermeasureId
  const statusConfig = STATUS_CONFIG[cm.status] || STATUS_CONFIG.gap
  const StatusIcon = statusConfig.icon

  return (
    <div className="flex items-center justify-between py-2 px-3 bg-muted/30 rounded-md">
      <div className="flex items-center gap-2 flex-1 min-w-0">
        <Shield className="h-4 w-4 text-muted-foreground flex-shrink-0" />
        <span className="text-sm truncate">{cmName}</span>
      </div>
      <div className="flex items-center gap-2">
        {cm.owner && (
          <span className="text-xs text-muted-foreground">{cm.owner}</span>
        )}
        <Badge variant="outline" className={`text-xs ${statusConfig.color}`}>
          <StatusIcon className="h-3 w-3 mr-1" />
          {statusConfig.label}
        </Badge>
      </div>
    </div>
  )
}

interface ThreatCardProps {
  threat: ComponentThreat
  componentName: string
}

function ThreatCard({ threat, componentName }: ThreatCardProps) {
  const [isOpen, setIsOpen] = useState(false)

  // Calculate threat status based on countermeasures
  const stats = useMemo(() => {
    const activeCountermeasures = threat.countermeasures
    const total = activeCountermeasures.length
    const platform = activeCountermeasures.filter((cm) => cm.status === 'platform').length
    const gaps = activeCountermeasures.filter((cm) => cm.status === 'gap').length
    const planned = activeCountermeasures.filter((cm) => cm.status === 'planned').length
    const waived = activeCountermeasures.filter((cm) => cm.status === 'waived').length

    let status: 'mitigated' | 'addressable' | 'exposed' = 'exposed'
    if (gaps === 0 && total > 0) {
      status = 'mitigated'
    } else if (planned > 0 || waived > 0) {
      status = 'addressable'
    }

    return { total, platform, gaps, planned, waived, status }
  }, [threat.countermeasures])

  const statusColors = {
    mitigated: 'border-l-green-500 bg-green-50/50',
    addressable: 'border-l-yellow-500 bg-yellow-50/50',
    exposed: 'border-l-red-500 bg-red-50/50',
  }

  return (
    <Card className={`border-l-4 ${statusColors[stats.status]}`}>
      <CardHeader
        className="cursor-pointer hover:bg-muted/20 transition-colors py-3"
        onClick={() => setIsOpen(!isOpen)}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3 flex-1 min-w-0">
            {isOpen ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground flex-shrink-0" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
            )}
            <AlertTriangle className="h-4 w-4 text-muted-foreground flex-shrink-0" />
            <div className="flex-1 min-w-0">
              <CardTitle className="text-sm font-medium truncate">
                {threat.threatName || threat.threatId}
              </CardTitle>
              <p className="text-xs text-muted-foreground mt-0.5">
                Component: {componentName}
                {threat.sourceDiagramTitle && ` (${threat.sourceDiagramTitle})`}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <TaxonomyBadges entries={threat.taxonomyEntries} maxVisible={2} size="sm" />
            <Badge
              variant="outline"
              className={`text-xs ${
                stats.status === 'mitigated'
                  ? 'bg-green-100 text-green-800'
                  : stats.status === 'addressable'
                    ? 'bg-yellow-100 text-yellow-800'
                    : 'bg-red-100 text-red-800'
              }`}
            >
              {stats.status === 'mitigated'
                ? 'Mitigated'
                : stats.status === 'addressable'
                  ? 'Addressable'
                  : 'Exposed'}
            </Badge>
            <span className="text-xs text-muted-foreground">
              {stats.platform}/{stats.total} platform
            </span>
          </div>
        </div>
      </CardHeader>
      {isOpen && (
        <CardContent className="pt-0 pb-4">
          {threat.threatDescription && (
            <p className="text-sm text-muted-foreground mb-4">{threat.threatDescription}</p>
          )}
          {threat.countermeasures.length > 0 ? (
            <div className="space-y-2">
              <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                Countermeasures ({threat.countermeasures.length})
              </h4>
              <div className="space-y-1">
                {threat.countermeasures
                  .map((cm) => (
                    <CountermeasureRow key={cm.id} cm={cm} />
                  ))}
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground italic">
              No countermeasures defined for this threat.
            </p>
          )}
        </CardContent>
      )}
    </Card>
  )
}

export function ReadOnlyThreatAnalysisView({
  diagrams,
  threatAnalysisData,
  className,
}: ReadOnlyThreatAnalysisViewProps) {
  const [viewMode, setViewMode] = useState<'cards' | 'table'>('cards')
  const [filterDfd, setFilterDfd] = useState<string | null>(null)

  // Ensure diagrams is an array
  const safeDiagrams = diagrams ?? []

  // Convert backend threat data to ComponentThreat format for display
  const allThreats = useMemo(() => {
    if (threatAnalysisData) {
      return threatAnalysisData.threats.map(convertSharedThreatToComponentThreat)
    }
    return []
  }, [threatAnalysisData])

  // Build component name lookup from diagrams or from backend data
  const componentNameMap = useMemo(() => {
    const map = new Map<string, string>()

    if (threatAnalysisData) {
      // Build from backend threat data
      threatAnalysisData.threats.forEach((threat) => {
        if (threat.type === 'component' && threat.nodeId) {
          map.set(threat.nodeId, threat.componentName || 'Unknown Component')
        } else if (threat.type === 'flow' && threat.edgeId) {
          map.set(threat.edgeId, threat.flowLabel || 'Data Flow')
        }
      })
    } else {
      // Build from canvas data
      safeDiagrams.forEach((diagram) => {
        const nodes = diagram.canvasData?.nodes || []
        nodes.forEach((node) => {
          const n = node as DiagramNode
          const label = (n.data as { label?: string })?.label || n.type || 'Unknown'
          map.set(n.id, label)
        })
        // Also map edges
        const edges = diagram.canvasData?.edges || []
        edges.forEach((edge) => {
          const e = edge as { id: string; data?: { label?: string } }
          map.set(e.id, e.data?.label || 'Data Flow')
        })
      })
    }
    return map
  }, [threatAnalysisData, safeDiagrams])

  // Get unique DFDs for filter
  const dfdOptions = useMemo(() => {
    if (threatAnalysisData) {
      // Extract unique DFDs from threat data
      const dfdMap = new Map<string, string>()
      threatAnalysisData.threats.forEach((threat) => {
        if (threat.dfdId && threat.dfdName) {
          dfdMap.set(threat.dfdId, threat.dfdName)
        }
      })
      return Array.from(dfdMap.entries()).map(([id, name]) => ({ id, name }))
    }
    return safeDiagrams.map((d) => ({ id: String(d.id), name: d.name }))
  }, [threatAnalysisData, safeDiagrams])

  // Filter threats by DFD (exclude triaged)
  const filteredThreats = useMemo(() => {
    const activeThreats = allThreats.filter((t) => isActiveThreat(t.triageStatus))
    if (!filterDfd) return activeThreats
    return activeThreats.filter((t) => t.sourceDiagramId === filterDfd || t.diagramId === filterDfd)
  }, [allThreats, filterDfd])

  // Calculate summary stats
  const stats = useMemo(() => {
    let exposed = 0
    let addressable = 0
    let mitigated = 0

    filteredThreats.forEach((threat) => {
      const activeCountermeasures = threat.countermeasures
      const gaps = activeCountermeasures.filter((cm) => cm.status === 'gap').length
      const planned = activeCountermeasures.filter((cm) => cm.status === 'planned').length
      const waived = activeCountermeasures.filter((cm) => cm.status === 'waived').length

      if (gaps === 0 && activeCountermeasures.length > 0) {
        mitigated++
      } else if (planned > 0 || waived > 0) {
        addressable++
      } else {
        exposed++
      }
    })

    return { exposed, addressable, mitigated, total: filteredThreats.length }
  }, [filteredThreats])

  if (allThreats.length === 0) {
    return (
      <div className={`flex flex-col items-center justify-center py-12 ${className}`}>
        <Shield className="h-12 w-12 text-muted-foreground/50 mb-4" />
        <h3 className="text-lg font-medium mb-2">No Threats Identified</h3>
        <p className="text-muted-foreground text-sm text-center max-w-md">
          No threats have been identified for this threat model yet. Threats are generated when
          components are added to the data flow diagrams.
        </p>
      </div>
    )
  }

  return (
    <div className={className}>
      {/* Header with filters and view toggle */}
      <div className="flex items-center justify-between mb-4 px-4 py-2 bg-muted/30 rounded-lg">
        <div className="flex items-center gap-4">
          <h2 className="font-semibold">Threat Analysis</h2>
          {/* DFD Filter */}
          {dfdOptions.length > 1 && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Filter by DFD:</span>
              <select
                value={filterDfd || ''}
                onChange={(e) => setFilterDfd(e.target.value || null)}
                className="text-sm border rounded-md px-2 py-1 bg-background"
              >
                <option value="">All DFDs</option>
                {dfdOptions.map((dfd) => (
                  <option key={dfd.id} value={dfd.id}>
                    {dfd.name}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
        <div className="flex items-center gap-4">
          {/* Summary badges */}
          <div className="flex items-center gap-2 text-sm">
            {stats.exposed > 0 && (
              <Badge variant="outline" className="bg-red-100 text-red-800">
                {stats.exposed} exposed
              </Badge>
            )}
            {stats.addressable > 0 && (
              <Badge variant="outline" className="bg-yellow-100 text-yellow-800">
                {stats.addressable} addressable
              </Badge>
            )}
            {stats.mitigated > 0 && (
              <Badge variant="outline" className="bg-green-100 text-green-800">
                {stats.mitigated} mitigated
              </Badge>
            )}
          </div>
          {/* View toggle */}
          <div className="flex items-center rounded-lg border bg-background p-1">
            <Button
              variant={viewMode === 'cards' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('cards')}
              className="rounded-md px-3 h-7 text-xs"
            >
              Cards
            </Button>
            <Button
              variant={viewMode === 'table' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('table')}
              className="rounded-md px-3 h-7 text-xs"
            >
              Table
            </Button>
          </div>
        </div>
      </div>

      {/* Content */}
      {viewMode === 'cards' ? (
        <div className="space-y-3 px-4">
          {filteredThreats.map((threat) => (
            <ThreatCard
              key={threat.id}
              threat={threat}
              componentName={componentNameMap.get(threat.componentId) || 'Unknown'}
            />
          ))}
        </div>
      ) : (
        <div className="px-4">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Component</TableHead>
                <TableHead>Threat</TableHead>
                <TableHead>Classifications</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Countermeasures</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredThreats.map((threat) => {
                // Use threat metadata from ComponentThreat
                const activeCountermeasures = threat.countermeasures
                const gaps = activeCountermeasures.filter((cm) => cm.status === 'gap').length
                const planned = activeCountermeasures.filter((cm) => cm.status === 'planned').length
                const platform = activeCountermeasures.filter((cm) => cm.status === 'platform').length

                let status: 'mitigated' | 'addressable' | 'exposed' = 'exposed'
                if (gaps === 0 && activeCountermeasures.length > 0) {
                  status = 'mitigated'
                } else if (planned > 0) {
                  status = 'addressable'
                }

                return (
                  <TableRow key={threat.id}>
                    <TableCell className="font-medium">
                      {componentNameMap.get(threat.componentId) || 'Unknown'}
                      {threat.sourceDiagramTitle && (
                        <span className="text-xs text-muted-foreground block">
                          {threat.sourceDiagramTitle}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>{threat.threatName || threat.threatId}</TableCell>
                    <TableCell>
                      <TaxonomyBadges entries={threat.taxonomyEntries} maxVisible={3} />
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={`text-xs ${
                          status === 'mitigated'
                            ? 'bg-green-100 text-green-800'
                            : status === 'addressable'
                              ? 'bg-yellow-100 text-yellow-800'
                              : 'bg-red-100 text-red-800'
                        }`}
                      >
                        {status === 'mitigated'
                          ? 'Mitigated'
                          : status === 'addressable'
                            ? 'Addressable'
                            : 'Exposed'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <span className="text-sm">
                        {platform}/{activeCountermeasures.length}
                        {gaps > 0 && (
                          <span className="text-red-600 ml-1">({gaps} gaps)</span>
                        )}
                      </span>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}
