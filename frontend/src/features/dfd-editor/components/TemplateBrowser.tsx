import { useState, useMemo } from 'react'
import { Search, LayoutTemplate, Loader2, Package } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useDFDTemplates, fetchResolvedTemplate } from '@/features/libraries/api/libraries'
import type { DFDTemplate } from '@/features/libraries/types/libraries'
import type { DiagramNode, DataFlowEdge } from '../types'
import { formatCategoryLabel } from '../types'

interface TemplateBrowserProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onInsert: (nodes: DiagramNode[], edges: DataFlowEdge[]) => void
  threatModelId?: string
}

type SortOption = 'newest' | 'name'

export function TemplateBrowser({
  open,
  onOpenChange,
  onInsert,
  threatModelId,
}: TemplateBrowserProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [sortBy, setSortBy] = useState<SortOption>('newest')
  const [filterBy, setFilterBy] = useState<string>('all')

  const {
    data: templates,
    isLoading,
    isError,
  } = useDFDTemplates(threatModelId)

  // Derive unique categories from actual template data
  const availableCategories = useMemo(() => {
    if (!templates) return []
    const categorySet = new Set<string>()
    for (const t of templates) {
      if (t.category) categorySet.add(t.category)
    }
    return Array.from(categorySet).sort((a, b) =>
      formatCategoryLabel(a).localeCompare(formatCategoryLabel(b))
    )
  }, [templates])

  const filteredTemplates = useMemo(() => {
    if (!templates) return []

    return templates
      .filter((template) => {
        // Search filter
        const query = searchQuery.toLowerCase()
        const matchesSearch =
          !query ||
          template.name.toLowerCase().includes(query) ||
          (template.description?.toLowerCase().includes(query) ?? false) ||
          (template.category?.toLowerCase().includes(query) ?? false)

        // Category filter
        const matchesCategory = filterBy === 'all' || template.category === filterBy

        return matchesSearch && matchesCategory
      })
      .sort((a, b) => {
        switch (sortBy) {
          case 'newest':
            return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
          case 'name':
            return a.name.localeCompare(b.name)
          default:
            return 0
        }
      })
  }, [templates, searchQuery, filterBy, sortBy])

  const [insertingTemplateId, setInsertingTemplateId] = useState<number | null>(null)

  const handleInsert = async (template: DFDTemplate) => {
    setInsertingTemplateId(template.id)

    try {
      // Fetch resolved template with component_refs resolved to component_library_ids
      const resolvedTemplate = await fetchResolvedTemplate(template.id)

      // Check for unresolved component refs
      const unresolvedRefs = resolvedTemplate.resolutionResults.filter((r) => !r.resolved)
      if (unresolvedRefs.length > 0) {
        // Log warning but still allow insertion
        const unresolvedNames = unresolvedRefs.map((r) => r.componentRef).join(', ')
        console.warn(`Some components could not be resolved: ${unresolvedNames}`)
      }

      const nodes = (resolvedTemplate.canvasData?.nodes ?? []) as DiagramNode[]
      const edges = (resolvedTemplate.canvasData?.edges ?? []) as DataFlowEdge[]
      onInsert(nodes, edges)
      setSearchQuery('')
      setFilterBy('all')
      onOpenChange(false)
    } catch (error) {
      console.error('Failed to resolve template:', error)
    } finally {
      setInsertingTemplateId(null)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-5xl max-h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-xl">
            <LayoutTemplate className="h-5 w-5" />
            Choose a Template
          </DialogTitle>
          <DialogDescription>
            Browse and insert pre-built diagram templates to accelerate your threat modeling
          </DialogDescription>
        </DialogHeader>

        {/* Search and Sort row */}
        <div className="flex gap-4 items-center">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search templates..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>
          <Select value={sortBy} onValueChange={(value) => setSortBy(value as SortOption)}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Sort by" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="newest">Newest</SelectItem>
              <SelectItem value="name">Name A-Z</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Filter tabs - FIX: Use static categories for stable UI */}
        <div className="flex gap-1 flex-wrap border-b pb-2">
          <Button
            variant={filterBy === 'all' ? 'default' : 'ghost'}
            size="sm"
            onClick={() => setFilterBy('all')}
            className="h-8"
          >
            All Templates
          </Button>
          {availableCategories.map((category) => (
            <Button
              key={category}
              variant={filterBy === category ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setFilterBy(category)}
              className="h-8"
            >
              {formatCategoryLabel(category)}
            </Button>
          ))}
        </div>

        {/* Template grid */}
        <div className="flex-1 min-h-0 overflow-y-auto -mx-2 px-2">
          {isLoading && (
            <div className="flex items-center justify-center h-64">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          )}

          {isError && (
            <div className="flex items-center justify-center h-64 text-muted-foreground">
              Failed to load templates
            </div>
          )}

          {!isLoading && !isError && filteredTemplates.length === 0 && (
            <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
              <LayoutTemplate className="h-12 w-12 mb-2 opacity-50" />
              <p>No templates found</p>
            </div>
          )}

          {!isLoading && !isError && filteredTemplates.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pb-4">
              {filteredTemplates.map((template) => {
                const isInserting = insertingTemplateId === template.id

                return (
                  <button
                    key={template.id}
                    onClick={() => handleInsert(template)}
                    disabled={insertingTemplateId !== null}
                    className="flex flex-col w-full h-full text-left p-4 border rounded-lg hover:border-primary hover:bg-primary/5 transition-colors group disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {/* Header: Title + Category */}
                    <div className="w-full mb-2">
                      <h3 className="font-semibold text-sm leading-tight group-hover:text-primary mb-1 flex items-center gap-2">
                        {isInserting && <Loader2 className="h-3 w-3 animate-spin" />}
                        {template.name}
                      </h3>
                      {template.category && (
                        <Badge variant="secondary" className="text-xs max-w-[120px] truncate">
                          {formatCategoryLabel(template.category)}
                        </Badge>
                      )}
                    </div>

                    {/* Description */}
                    <p className="text-sm text-muted-foreground line-clamp-2 mb-3 flex-1">
                      {template.description || 'No description'}
                    </p>

                    {/* Footer: Source Pack + Diagram Type */}
                    <div className="flex items-center justify-between text-xs text-muted-foreground w-full mt-auto">
                      {template.sourcePackName && (
                        <span className="flex items-center gap-1">
                          <Package className="h-3 w-3" />
                          {template.sourcePackName}
                        </span>
                      )}
                      {template.diagramType && (
                        <span>{template.diagramType}</span>
                      )}
                    </div>
                  </button>
                )
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end pt-2 border-t">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
