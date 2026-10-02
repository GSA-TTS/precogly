import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import type { ReportTriagedThreat } from '@/features/reports/types/report'
import { ReportSection } from '../ReportSection'

interface TriagedThreatsSectionProps {
  triagedThreats: ReportTriagedThreat[]
}

export function TriagedThreatsSection({ triagedThreats }: TriagedThreatsSectionProps) {
  if (triagedThreats.length === 0) {
    return (
      <ReportSection title="Triaged Threats" defaultOpen={false}>
        <p className="text-sm text-muted-foreground">No triaged threats.</p>
      </ReportSection>
    )
  }

  return (
    <ReportSection title="Triaged Threats" defaultOpen={false}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Threat</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Target</TableHead>
            <TableHead>Triage Status</TableHead>
            <TableHead>Rationale</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {triagedThreats.map((threat) => (
            <TableRow key={threat.id}>
              <TableCell className="font-medium">{threat.threatName}</TableCell>
              <TableCell>
                <Badge variant="outline">{threat.type}</Badge>
              </TableCell>
              <TableCell>{threat.componentName || threat.flowLabel || '—'}</TableCell>
              <TableCell>
                <Badge variant="outline">{threat.triageStatus}</Badge>
              </TableCell>
              <TableCell className="text-sm text-muted-foreground">
                {threat.decisionRationale || '—'}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </ReportSection>
  )
}
