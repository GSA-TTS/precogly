import { useMemo, useCallback } from 'react'
import { ExternalLink } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { ScrollArea } from '@/components/ui/scroll-area'
import type { CanvasData } from '../../types'
import type { ComponentThreat, CountermeasureStatus } from '../../types/threat-analysis'
import { deriveThreatStatus, THREAT_STATUS_CONFIG } from '../../types/threat-analysis'
import { isActiveThreat } from '@/types/triage'
import type { TaxonomyEntry } from '@/types/domain'
import { TaxonomyBadges } from '@/components/shared/TaxonomyBadges'
import { getAncestryPath, buildNodesMap } from './hierarchy-utils'
import { useTechnologies } from '../../api/component-library'

interface TableViewProps {
  canvasData: CanvasData
  componentThreats: ComponentThreat[]
  onCountermeasureStatusChange: (
    componentThreatId: string,
    countermeasureId: string,
    status: CountermeasureStatus
  ) => void
  onSelectThreat: (componentId: string, threatId: string) => void
}

interface FlattenedThreat {
  componentThreatId: string
  componentId: string
  componentLabel: string
  componentType: string
  technology?: string
  parentPath?: string
  threatId: string
  threatName: string
  taxonomyEntries: TaxonomyEntry[]
  status: 'exposed' | 'addressable' | 'mitigated'
  countermeasuresTotal: number
  countermeasuresResolved: number
  gaps: number
}

export function TableView({
  canvasData,
  componentThreats,
  onCountermeasureStatusChange: _onCountermeasureStatusChange,
  onSelectThreat,
}: TableViewProps) {
  // Mark as used - inline editing will be added later
  void _onCountermeasureStatusChange
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

  // Build nodes map once for hierarchy lookups
  const nodesMap = useMemo(
    () => buildNodesMap(canvasData.nodes),
    [canvasData.nodes]
  )

  // Flatten all threats into table rows
  const flattenedThreats = useMemo((): FlattenedThreat[] => {
    const rows: FlattenedThreat[] = []

    componentThreats
      .filter((ct) => isActiveThreat(ct.triageStatus))
      .forEach((ct) => {
        if (!ct.threatName) return

        const isDataflow = ct.threatType === 'dataflow'
        let componentLabel: string
        let componentType: string
        let technologyName = ''
        let parentPath: string | undefined

        if (isDataflow) {
          const edge = canvasData.edges.find((e) => e.id === ct.componentId)
          componentLabel = ct.dataflowLabel || ct.componentName || (edge?.data as { label?: string })?.label || 'Data Flow'
          componentType = 'dataFlow'
        } else {
          const node = canvasData.nodes.find((n) => n.id === ct.componentId)
          if (!node) return

          componentLabel = String(node.data.label)
          componentType = node.type as string
          technologyName = resolveTechName((node.data as { technology?: string }).technology)

          if (node.type === 'process') {
            const ancestry = getAncestryPath(node.id, nodesMap)
            if (ancestry.length > 1) {
              parentPath = ancestry
                .slice(0, -1)
                .map((a) => {
                  const aLabel = String(a.data.label)
                  const aTech = resolveTechName((a.data as { technology?: string }).technology)
                  return aLabel.toLowerCase().includes('new ') ? (aTech || aLabel) : aLabel
                })
                .join(' > ')
            }
          }
        }

        const status = deriveThreatStatus(ct.countermeasures)
        const resolved = ct.countermeasures.filter(
          (cm) => cm.status !== 'gap'
        ).length
        const gaps = ct.countermeasures.filter((cm) => cm.status === 'gap').length

        rows.push({
          componentThreatId: ct.id,
          componentId: ct.componentId,
          componentLabel,
          componentType,
          technology: technologyName,
          parentPath,
          threatId: ct.threatId,
          threatName: ct.threatName,
          taxonomyEntries: ct.taxonomyEntries || [],
          status,
          countermeasuresTotal: ct.countermeasures.length,
          countermeasuresResolved: resolved,
          gaps,
        })
      })

    // Sort by status (exposed first, then addressable, then mitigated)
    const statusOrder = { exposed: 0, addressable: 1, mitigated: 2 }
    rows.sort((a, b) => statusOrder[a.status] - statusOrder[b.status])

    return rows
  }, [componentThreats, canvasData.nodes, nodesMap, resolveTechName])

  // Summary stats
  const stats = useMemo(() => {
    const exposed = flattenedThreats.filter((t) => t.status === 'exposed').length
    const addressable = flattenedThreats.filter((t) => t.status === 'addressable').length
    const mitigated = flattenedThreats.filter((t) => t.status === 'mitigated').length
    return { total: flattenedThreats.length, exposed, addressable, mitigated }
  }, [flattenedThreats])

  return (
    <div className="flex flex-col h-full">
      {/* Summary bar */}
      <div className="px-4 py-3 border-b flex items-center gap-6">
        <div className="text-sm">
          <span className="font-medium">{stats.total}</span>{' '}
          <span className="text-muted-foreground">total threats</span>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-red-500" />
            <span className="text-sm">
              <span className="font-medium">{stats.exposed}</span>{' '}
              <span className="text-muted-foreground">exposed</span>
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-yellow-500" />
            <span className="text-sm">
              <span className="font-medium">{stats.addressable}</span>{' '}
              <span className="text-muted-foreground">in progress</span>
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-green-500" />
            <span className="text-sm">
              <span className="font-medium">{stats.mitigated}</span>{' '}
              <span className="text-muted-foreground">mitigated</span>
            </span>
          </div>
        </div>
      </div>

      {/* Table */}
      <ScrollArea className="flex-1">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[50px]">Status</TableHead>
              <TableHead>Component</TableHead>
              <TableHead>Technology</TableHead>
              <TableHead>Threat</TableHead>
              <TableHead>Classifications</TableHead>
              <TableHead className="text-center">Countermeasures</TableHead>
              <TableHead className="text-center">Gaps</TableHead>
              <TableHead className="w-[80px]"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {flattenedThreats.map((row) => {
              const statusConfig = THREAT_STATUS_CONFIG[row.status]

              return (
                <TableRow key={row.componentThreatId}>
                  <TableCell>
                    <span
                      className="inline-block w-2 h-2 rounded-full"
                      style={{ backgroundColor: statusConfig.color }}
                      title={statusConfig.label}
                    />
                  </TableCell>
                  <TableCell>
                    {row.parentPath && (
                      <div className="text-[10px] text-muted-foreground leading-tight">
                        {row.parentPath}
                      </div>
                    )}
                    <div className="font-medium">{row.componentLabel}</div>
                    <div className="text-xs text-muted-foreground capitalize">
                      {row.componentType === 'dataFlow' ? 'Data Flow' : row.componentType}
                    </div>
                  </TableCell>
                  <TableCell>
                    {row.technology ? (
                      <span className="text-sm">{row.technology}</span>
                    ) : (
                      <span className="text-sm text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <span className="font-medium">{row.threatName}</span>
                  </TableCell>
                  <TableCell>
                    <TaxonomyBadges entries={row.taxonomyEntries} maxVisible={3} />
                  </TableCell>
                  <TableCell className="text-center">
                    <span className="text-sm">
                      {row.countermeasuresResolved}/{row.countermeasuresTotal}
                    </span>
                  </TableCell>
                  <TableCell className="text-center">
                    {row.gaps > 0 ? (
                      <Badge variant="outline" className="bg-red-100 text-red-700">
                        {row.gaps}
                      </Badge>
                    ) : (
                      <span className="text-sm text-muted-foreground">0</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-8 w-8 p-0"
                      onClick={() => onSelectThreat(row.componentId, row.componentThreatId)}
                      title="View details"
                    >
                      <ExternalLink className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              )
            })}

            {flattenedThreats.length === 0 && (
              <TableRow>
                <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                  No threats found. Add technology to your components to see suggested threats.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </ScrollArea>
    </div>
  )
}
