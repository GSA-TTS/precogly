/** Imported rollups are source declarations, never runtime verification. */
export interface ControlRollupEntry {
  controlId: string
  aggregateStatus: string
  countermeasureCount: number
}

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

export function readControlRollup(metadata: unknown): ControlRollupEntry[] {
  const cdx = record(record(metadata).cyclonedx)
  const keptMetadata = record(record(cdx.passthrough).metadata)
  const properties = [...(Array.isArray(keptMetadata.properties) ? keptMetadata.properties : []), ...(Array.isArray(cdx.foreignProperties) ? cdx.foreignProperties : []), ...(Array.isArray(cdx.foreign_properties) ? cdx.foreign_properties : [])]
  const candidates = properties.map(record).filter((item) => item.name === 'resp:control-rollup' || item.name === 'crm:control-rollup')
  // Conflicting/duplicate declarations must not silently pick a preferred truth.
  if (candidates.length !== 1 || typeof candidates[0].value !== 'string') return []
  let rows: unknown
  try { rows = JSON.parse(candidates[0].value) } catch { return [] }
  if (!Array.isArray(rows) || rows.length > 2000) return []
  const seen = new Set<string>()
  const result: ControlRollupEntry[] = []
  for (const raw of rows) {
    const row = record(raw)
    const controlId = row.controlId ?? row.control_id
    const status = row.aggregateStatus ?? row.aggregate_status
    const count = row.cmCount ?? row.cm_count
    if (typeof controlId !== 'string' || !/^[A-Z]{2}-\d+(?:\(\d+\))?$/.test(controlId) || seen.has(controlId)) return []
    if (typeof status !== 'string' || !['gap', 'recommended', 'planned', 'in-progress', 'in_progress', 'implemented', 'verified', 'rejected', 'waived', 'platform', 'decommissioned'].includes(status)) return []
    if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 1) return []
    seen.add(controlId)
    result.push({ controlId, aggregateStatus: status, countermeasureCount: count })
  }
  return result.sort((a, b) => a.controlId.localeCompare(b.controlId))
}
