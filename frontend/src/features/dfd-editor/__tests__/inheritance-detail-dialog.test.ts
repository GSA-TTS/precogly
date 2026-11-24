import { createElement, type ReactNode } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { expect, it, vi } from 'vitest'
import type { AnalysisCountermeasure, AnalysisThreat } from '../types/threat-analysis'

// Render the real dialog content without a portal/DOM dependency. API mutations
// must remain unused: this contract tests source presentation, not a live model.
vi.mock('@/components/ui/dialog', () => {
  const wrapper = ({ children }: { children: ReactNode }) => createElement('div', null, children)
  return { Dialog: wrapper, DialogContent: wrapper, DialogDescription: wrapper,
    DialogFooter: wrapper, DialogHeader: wrapper, DialogTitle: wrapper }
})
vi.mock('@/features/threat-models/api/threats', () => ({
  useSetCountermeasureTargets: () => ({ mutate: vi.fn() }),
  useCountermeasure: () => ({ data: undefined }),
  useUpdateCountermeasure: () => ({ mutate: vi.fn() }),
}))

import { CountermeasureDetailDialog } from '../components/threat-analysis/CountermeasureDetailDialog'

const threat = {
  backendThreatId: 1, displayNumber: 'T1', threatName: 'Synthetic threat',
  targets: [], countermeasures: [],
} as unknown as AnalysisThreat

function render(metadata: unknown) {
  const countermeasure: AnalysisCountermeasure = {
    id: 'cm-1', countermeasureId: 'custom', threatId: 'threat-1', status: 'gap',
    countermeasureName: 'Synthetic control', createdAt: '', updatedAt: '',
    formatMetadata: metadata as Record<string, unknown>, standardMappings: [],
  }
  const noop = () => {}
  return renderToStaticMarkup(createElement(CountermeasureDetailDialog, {
    threatModelId: '1', threat, countermeasure, onClose: noop,
    onStatusChange: noop, onAssignOwner: noop, onPriorityChange: noop,
    onDueDateChange: noop, onExternalTicketChange: noop, onRequestDelete: noop,
    onEditCompliance: noop, onOpenThreat: noop,
  }))
}

it('renders provider and responsibility source in the real detail dialog', () => {
  const html = render({ cyclonedx: { providingSystem: 'Platform', responsibilitySource: 'crm' } })
  expect(html).toContain('Providing system: ')
  expect(html).toContain('Platform')
  expect(html).toContain('Responsibility source: ')
  expect(html).toContain('crm')
  expect(html).toContain('Imported source metadata is not verification of deployed controls.')
  expect(html).toContain('data-countermeasure-status="gap"')
})

it('escapes legacy provider metadata and hides absent inheritance sections', () => {
  const html = render({ cyclonedx: { providing_system: '<script>unsafe</script>', responsibility_source: 'legacy' } })
  expect(html).toContain('&lt;script&gt;unsafe&lt;/script&gt;')
  expect(html).not.toContain('<script>')
  expect(render({})).not.toContain('Declared inheritance source')
  expect(render({ cyclonedx: [] })).not.toContain('Declared inheritance source')
})
