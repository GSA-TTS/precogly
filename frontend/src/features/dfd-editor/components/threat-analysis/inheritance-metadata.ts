/** Display source declarations only; never derive verification or control status. */

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

export function inheritanceMetadata(metadata: unknown, implementedByParty?: string) {
  const cdx = record(record(metadata).cyclonedx)
  return {
    providingSystem: text(cdx.providingSystem) || text(cdx.providing_system) || text(implementedByParty),
    responsibilitySource: text(cdx.responsibilitySource) || text(cdx.responsibility_source),
  }
}
