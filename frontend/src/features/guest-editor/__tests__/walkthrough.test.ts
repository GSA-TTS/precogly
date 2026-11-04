import { describe, expect, it } from 'vitest'
import {
  buildWalkthroughGuestState,
  computeFips199HighWaterMark,
  evaluateControlBaseline,
} from '../lib/walkthrough'

describe('guest FIPS 199 walkthrough (#96)', () => {
  it('computes high-water-mark categorization across selected 800-60 types', () => {
    const fips = computeFips199HighWaterMark([
      { id: 'C.3.5.1', confidentiality: 'low', integrity: 'moderate', availability: 'low' },
      { id: 'D.8.1', confidentiality: 'high', integrity: 'moderate', availability: 'low' },
    ])
    expect(fips).toEqual({
      confidentiality: 'high',
      integrity: 'moderate',
      availability: 'low',
      overall: 'high',
    })
  })

  it('classifies baseline controls into inherited, shared, and gap for selected packs', () => {
    const evaluated = evaluateControlBaseline('moderate', ['cloudgov-paas'])
    const byId = Object.fromEntries(evaluated.map((c) => [c.id, c.state]))
    expect(byId['SC-7']).toBe('inherited')
    expect(byId['AC-2']).toBe('shared')
    expect(byId['CM-6']).toBe('gap')
  })

  it('builds a valid CycloneDX 2.0 TM-BOM JSON + YAML that round-trips into the guest editor', () => {
    const { json, yaml, deserialized } = buildWalkthroughGuestState({
      systemName: 'Acquisition Portal',
      systemDescription: 'FPDF test walkthrough',
      infoTypes: [
        { id: 'C.2.8.1', confidentiality: 'moderate', integrity: 'moderate', availability: 'low' },
      ],
      patternIds: ['cloudgov-paas'],
      selectedThreatIds: ['t-cg-authz'],
    })

    const doc = JSON.parse(json)
    expect(doc.specFormat).toBe('CycloneDX')
    expect(doc.specVersion).toBe('2.0')
    expect(
      doc.metadata.component.properties.find(
        (p: { name: string }) => p.name === 'fips199:categorization'
      )?.value
    ).toBe('moderate')
    expect(yaml).toContain('specFormat: "CycloneDX"')
    expect(deserialized.title).toBe('Acquisition Portal')
    expect(deserialized.nodes.length).toBeGreaterThan(4)
    expect(deserialized.countermeasures.length).toBeGreaterThan(5)
    expect(deserialized.threats.some((t) => t.name.includes('Broken object-level'))).toBe(true)
  })
})
