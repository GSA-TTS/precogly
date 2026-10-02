import type { ReportData, ReportThreat } from '../types/report'
import { formatTaxonomyEntryLabel } from '@/types/domain'

function downloadCsv(filename: string, headers: string[], rows: string[][]): void {
  const csvContent = [
    headers.join(','),
    ...rows.map(row =>
      row.map(cell => `"${String(cell ?? '').replace(/"/g, '""')}"`).join(',')
    ),
  ].join('\n')

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

function slugify(name: string): string {
  return name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '')
}

type ThreatWithContext = { threat: ReportThreat; context: string }

function flattenThreats(data: ReportData): ThreatWithContext[] {
  const out: ThreatWithContext[] = []
  for (const [context, threats] of Object.entries(data.threatAnalysis.componentThreats)) {
    for (const threat of threats) out.push({ threat, context })
  }
  for (const [context, threats] of Object.entries(data.threatAnalysis.dataFlowThreats)) {
    for (const threat of threats) out.push({ threat, context })
  }
  return out
}

export function exportThreatsCSV(data: ReportData, modelName: string): void {
  const headers = [
    'Threat Name',
    'Description',
    'STRIDE Category',
    'Classifications',
    'Inherent Severity',
    'Residual Severity',
    'Status',
    'Component / Data Flow',
  ]
  const rows = flattenThreats(data).map(({ threat, context }) => [
    threat.threatName,
    threat.threatDescription,
    threat.strideCategory ?? '',
    (threat.taxonomyEntries ?? []).map(e => formatTaxonomyEntryLabel(e)).join('; '),
    threat.inherentSeverity,
    threat.residualSeverity,
    threat.status,
    context,
  ])
  downloadCsv(`${slugify(modelName)}-threats.csv`, headers, rows)
}

export function exportCountermeasuresCSV(data: ReportData, modelName: string): void {
  const headers = [
    'Countermeasure',
    'Control Type',
    'Status',
    'Priority',
    'Compliance Standards',
    'Assigned Owner',
    'Inherited',
    'Inherited From',
    'Associated Threat',
    'Component / Data Flow',
  ]
  const rows: string[][] = []
  for (const { threat, context } of flattenThreats(data)) {
    for (const cm of threat.countermeasures) {
      rows.push([
        cm.countermeasureName,
        (cm.controlFunctions || []).join(', '),
        cm.status,
        cm.priority,
        (cm.complianceStandards ?? []).map(s => `${s.frameworkName} ${s.sectionCode}`).join('; '),
        cm.assignedOwnerEmail ?? '',
        cm.isInherited ? 'Yes' : 'No',
        cm.inheritedFromComponentName ?? cm.inheritedFromZoneName ?? '',
        threat.threatName,
        context,
      ])
    }
  }
  downloadCsv(`${slugify(modelName)}-countermeasures.csv`, headers, rows)
}

export function exportRisksCSV(data: ReportData, modelName: string): void {
  const headers = [
    'Risk Name',
    'Description',
    'Inherent Score',
    'Inherent Level',
    'Residual Score',
    'Residual Level',
    'Owner',
  ]
  const rows = data.risks.map(risk => [
    risk.name,
    risk.description,
    String(risk.inherentScore),
    risk.inherentLevel,
    String(risk.residualScore),
    risk.residualLevel,
    risk.ownerEmail ?? '',
  ])
  downloadCsv(`${slugify(modelName)}-risks.csv`, headers, rows)
}

export function exportComplianceCSV(data: ReportData, modelName: string): void {
  const headers = [
    'Framework',
    'Total Requirements',
    'Covered',
    'Coverage %',
  ]
  const rows = data.compliance.frameworks.map(fw => [
    fw.name,
    String(fw.totalRequirements),
    String(fw.coveredRequirements),
    `${fw.coveragePercentage.toFixed(1)}%`,
  ])
  downloadCsv(`${slugify(modelName)}-compliance.csv`, headers, rows)
}
