import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { createElement } from 'react'
import { inheritanceMetadata } from '../components/threat-analysis/inheritance-metadata'
import { CountermeasureCard } from '../components/threat-analysis/CountermeasureCard'
import type { AnalysisCountermeasure } from '../types/threat-analysis'

describe('declared inheritance metadata', () => {
  it('handles API camel case and legacy snake case', () => {
    for (const cyclonedx of [
      { providingSystem: 'Platform', responsibilitySource: 'crm' },
      { providing_system: 'Platform', responsibility_source: 'crm' },
    ]) {
      expect(inheritanceMetadata({ cyclonedx })).toEqual({ providingSystem: 'Platform', responsibilitySource: 'crm' })
    }
  })

  it('ignores malformed metadata and preserves party fallback', () => {
    for (const metadata of [null, undefined, [], 'invalid', { cyclonedx: [] }, { cyclonedx: { providingSystem: {}, responsibilitySource: false } }]) {
      expect(inheritanceMetadata(metadata, 'Platform')).toEqual({ providingSystem: 'Platform', responsibilitySource: '' })
    }
  })

  it('renders escaped source text without promoting a gap status', () => {
    const countermeasure: AnalysisCountermeasure = {
      id: 'cm-1', countermeasureId: 'custom', threatId: 'threat-1', status: 'gap',
      createdAt: '', updatedAt: '', countermeasureName: 'Control',
      formatMetadata: { cyclonedx: { providingSystem: '<script>bad</script>', responsibilitySource: 'crm' } },
    }
    const html = renderToStaticMarkup(createElement(CountermeasureCard, {
      countermeasure, isOpen: false, onOpen: () => {},
    }))
    expect(html).toContain('Declared provider: &lt;script&gt;bad&lt;/script&gt;')
    expect(html).toContain('Source: crm')
    expect(html).toContain('data-countermeasure-status="gap"')
    expect(html).not.toContain('<script>')
  })
})
