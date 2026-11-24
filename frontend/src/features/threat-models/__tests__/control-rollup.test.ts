import { expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { readControlRollup } from '../components/workspace/control-rollup'
import { ControlRollup } from '../components/workspace/ControlRollup'

const rows = [{ control_id: 'AC-1', aggregate_status: 'gap', cm_count: 2 }]
function metadata(value: unknown, name = 'resp:control-rollup') {
  return { cyclonedx: { passthrough: { metadata: { properties: [{ name, value: JSON.stringify(value) }] } } } }
}

it('reads current metadata passthrough and legacy key', () => {
  for (const name of ['resp:control-rollup', 'crm:control-rollup']) {
    expect(readControlRollup(metadata(rows, name))).toEqual([{ controlId: 'AC-1', aggregateStatus: 'gap', countermeasureCount: 2 }])
  }
})

it('supports foreign property and camel-case row shapes', () => {
  expect(readControlRollup({ cyclonedx: { foreignProperties: [{ name: 'crm:control-rollup', value: JSON.stringify([{ controlId: 'AC-1', aggregateStatus: 'gap', cmCount: 2 }]) }] } })).toHaveLength(1)
})

it('preserves generator statuses rather than converting them to implementation claims', () => {
  for (const aggregate_status of ['recommended', 'in-progress', 'rejected', 'waived']) {
    expect(readControlRollup(metadata([{ ...rows[0], aggregate_status }]))[0].aggregateStatus).toBe(aggregate_status)
  }
})

it('keeps the full table when a rejected control accompanies another status', () => {
  const mixed = [rows[0], { control_id: 'AC-2', aggregate_status: 'rejected', cm_count: 1 }]
  expect(readControlRollup(metadata(mixed))).toHaveLength(2)
  const html = renderToStaticMarkup(createElement(ControlRollup, { metadata: metadata(mixed) }))
  expect(html).toContain('AC-1')
  expect(html).toContain('AC-2')
  expect(html).toContain('rejected')
})

it('rejects malformed, ambiguous, duplicate or untrusted row values', () => {
  for (const value of [null, {}, [{ ...rows[0], cm_count: -1 }], [{ ...rows[0], aggregate_status: '<script>' }], [rows[0], rows[0]], [{ ...rows[0], control_id: '<script>' }]]) expect(readControlRollup(metadata(value))).toEqual([])
  expect(readControlRollup({ cyclonedx: { foreignProperties: [{ name: 'resp:control-rollup', value: 'bad json' }] } })).toEqual([])
  const conflict = metadata(rows)
  conflict.cyclonedx.passthrough.metadata.properties.push({ name: 'crm:control-rollup', value: JSON.stringify(rows) })
  expect(readControlRollup(conflict)).toEqual([])
})

it('renders declared status without implying verification; absent metadata hides section', () => {
  const html = renderToStaticMarkup(createElement(ControlRollup, { metadata: metadata(rows) }))
  expect(html).toContain('not verification of deployed controls')
  expect(html).toContain('AC-1')
  expect(html).toContain('gap')
  expect(renderToStaticMarkup(createElement(ControlRollup, { metadata: {} }))).toBe('')
})
