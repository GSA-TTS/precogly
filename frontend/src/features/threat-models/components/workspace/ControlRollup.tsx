import { readControlRollup } from './control-rollup'

export function ControlRollup({ metadata }: { metadata: unknown }) {
  const entries = readControlRollup(metadata)
  if (entries.length === 0) return null
  return (
    <section aria-label="Imported control rollup" className="rounded-lg border p-4">
      <h3 className="text-sm font-medium">Imported control rollup</h3>
      <p className="mb-3 text-xs text-muted-foreground">Source-declared aggregate statuses; not verification of deployed controls.</p>
      <div className="max-h-80 overflow-auto">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Source control statuses and countermeasure counts</caption>
          <thead><tr><th scope="col">Control</th><th scope="col">Declared status</th><th scope="col">Countermeasures</th></tr></thead>
          <tbody>{entries.map((entry) => <tr key={entry.controlId}><th scope="row">{entry.controlId}</th><td>{entry.aggregateStatus}</td><td>{entry.countermeasureCount}</td></tr>)}</tbody>
        </table>
      </div>
    </section>
  )
}
