import { Cog, Database, User, ChevronRight, Building2, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import type { ComponentThreat } from '../../types/threat-analysis'
import { deriveThreatStatus } from '../../types/threat-analysis'
import { isActiveThreat } from '@/types/triage'
import type { ComponentTreeNode } from './hierarchy-utils'
import { ComponentDataAssetsDisplay } from './ComponentDataAssetsDisplay'

const nodeTypeIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  process: Cog,
  datastore: Database,
  humanActor: User,
  systemActor: Building2,
}

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

export function ComponentTreeItem({
  treeNode,
  componentThreats,
  selectedComponentId,
  collapsedNodes,
  onSelectComponent,
  onToggleCollapsed,
  resolveTechName,
  onRequestDeleteComponent,
}: {
  treeNode: ComponentTreeNode
  componentThreats: ComponentThreat[]
  selectedComponentId: string | null
  collapsedNodes: Set<string>
  onSelectComponent: (id: string) => void
  onToggleCollapsed: (id: string) => void
  resolveTechName: (value: string | undefined) => string
  onRequestDeleteComponent: (component: { id: number; name: string }) => void
}) {
  const { node, children, depth } = treeNode
  const Icon = nodeTypeIcons[node.type as string] || Cog
  const summary = getComponentThreatSummary(node.id, componentThreats)
  const isSelected = node.id === selectedComponentId
  const technologyName = resolveTechName((node.data as { technology?: string }).technology)
  const nodeLabel = String(node.data.label)
  const isDefaultLabel = nodeLabel.toLowerCase().includes('new ')
  const displayName = !isDefaultLabel ? nodeLabel : (technologyName || nodeLabel)
  const showSecondaryLabel = technologyName && !isDefaultLabel && nodeLabel !== technologyName
  const hasChildren = children.length > 0
  const isCollapsed = collapsedNodes.has(node.id)
  const componentId = (node.data as { componentId?: number }).componentId
  const isAnalysisOnly = (node.data as { isAnalysisOnly?: boolean }).isAnalysisOnly

  return (
    <>
      <div
        role="button"
        tabIndex={0}
        onClick={() => onSelectComponent(node.id)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            onSelectComponent(node.id)
          }
        }}
        className={cn(
          'group w-full text-left p-2 rounded-md transition-colors cursor-pointer',
          isSelected
            ? 'bg-slate-100 border border-slate-300'
            : 'hover:bg-slate-50'
        )}
        style={{ paddingLeft: `${8 + depth * 16}px` }}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 min-w-0">
            {/* Chevron for parents, spacer for leaves */}
            {hasChildren ? (
              <button
                type="button"
                className="flex-shrink-0 p-0.5 rounded hover:bg-slate-200 transition-colors"
                onClick={(e) => {
                  e.stopPropagation()
                  onToggleCollapsed(node.id)
                }}
                aria-label={isCollapsed ? `Expand ${displayName}` : `Collapse ${displayName}`}
              >
                <ChevronRight
                  className={cn(
                    'h-3 w-3 text-muted-foreground transition-transform',
                    !isCollapsed && 'rotate-90'
                  )}
                />
              </button>
            ) : (
              <span className="w-4 flex-shrink-0" />
            )}
            <Icon className="h-4 w-4 text-muted-foreground flex-shrink-0" />
            <div className="min-w-0">
              <div className="font-medium text-sm truncate">
                {displayName}
              </div>
              {showSecondaryLabel && (
                <div className="text-xs text-muted-foreground truncate">
                  {technologyName}
                </div>
              )}
            </div>
          </div>
          <div className="flex items-center gap-1 ml-2 shrink-0">
            {componentId !== undefined && isAnalysisOnly && (
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 opacity-0 group-hover:opacity-100 touch:opacity-100 transition-opacity text-muted-foreground hover:text-destructive"
                onClick={(e) => {
                  e.stopPropagation()
                  onRequestDeleteComponent({ id: componentId, name: displayName })
                }}
                aria-label={`Delete ${displayName}`}
                title="Delete component"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            )}
            {componentId !== undefined && !isAnalysisOnly && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="opacity-0 group-hover:opacity-100 touch:opacity-100 transition-opacity">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 text-muted-foreground pointer-events-none opacity-50"
                      disabled
                      aria-label={`Cannot delete ${displayName}`}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </span>
                </TooltipTrigger>
                <TooltipContent side="left">
                  This component was created in the DFD editor. You can delete it only where you created it.
                </TooltipContent>
              </Tooltip>
            )}
            {summary.exposed > 0 ? (
              <Badge variant="outline" className="bg-red-100 text-red-700 text-xs shrink-0">
                {summary.exposed} exposed
              </Badge>
            ) : summary.addressable > 0 ? (
              <Badge variant="outline" className="bg-yellow-100 text-yellow-700 text-xs shrink-0">
                {summary.addressable} in progress
              </Badge>
            ) : summary.total > 0 ? (
              <span className="text-xs text-muted-foreground shrink-0">
                No threats
              </span>
            ) : null}
          </div>
        </div>
        {summary.total > 0 && (
          <div className="flex items-center gap-1 mt-1" style={{ marginLeft: `${hasChildren ? 24 : 20}px` }}>
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
      </div>
      {/* Data assets inline under selected component */}
      {isSelected && (
        <ComponentDataAssetsDisplay
          componentId={(node.data as { componentId?: number }).componentId}
        />
      )}
      {/* Recursively render children when not collapsed */}
      {hasChildren && !isCollapsed && children.map((child) => (
        <ComponentTreeItem
          key={child.node.id}
          treeNode={child}
          componentThreats={componentThreats}
          selectedComponentId={selectedComponentId}
          collapsedNodes={collapsedNodes}
          onSelectComponent={onSelectComponent}
          onToggleCollapsed={onToggleCollapsed}
          resolveTechName={resolveTechName}
          onRequestDeleteComponent={onRequestDeleteComponent}
        />
      ))}
    </>
  )
}
