import {
  Document,
  Paragraph,
  Table,
  TextRun,
  HeadingLevel,
  ImageRun,
} from 'docx'
import type { ReportData, ReportThreat } from '../types/report'
import { formatTaxonomyEntryLabel } from '@/types/domain'
import {
  h1,
  h2,
  h3,
  para,
  placeholder,
  spacer,
  pageBreak,
  buildTable,
  downloadDocx,
  slugify,
  createDocumentStyles,
  createNumberingConfig,
  createPageProperties,
} from './wordHelpers'

// ---------------------------------------------------------------------------
// Flatten helpers (mirrors csvExport.ts)
// ---------------------------------------------------------------------------

type ThreatWithContext = { threat: ReportThreat; context: string }

const ACTOR_TYPE_LABELS: Record<string, string> = {
  user: 'User',
  power_user: 'Power User',
  administrator: 'Administrator',
  engineer: 'Engineer',
  third_party: 'Third Party',
  customer: 'Customer',
}

function formatActorType(actorType: string): string {
  return ACTOR_TYPE_LABELS[actorType] ?? actorType
}

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

// ---------------------------------------------------------------------------
// Section builders
// ---------------------------------------------------------------------------

function buildMetadataSection(data: ReportData): (Paragraph | Table)[] {
  const m = data.metadata
  const rows = [
    ['Threat Model Name', m.name],
    ['Criticality', m.criticality],
    ['Risk Scoring Method', m.riskScoringMethod],
    ['Owning Team', m.owningTeam ?? '—'],
    ['Created By', m.createdBy ?? '—'],
    ['Created', m.createdAt ?? '—'],
    ['Last Updated', m.updatedAt ?? '—'],
    ['Frameworks', m.frameworks.map((f) => f.name).join(', ') || '—'],
  ]

  return [
    h1('1. Document Information'),
    spacer(),
    buildTable([3000, 6360], ['Field', 'Value'], rows),
    spacer(),
  ]
}

function buildSummarySection(data: ReportData): (Paragraph | Table)[] {
  const s = data.summaryMetrics
  const statusRows = Object.entries(s.threatsByStatus).map(([k, v]) => [k, String(v)])
  const cmRows = Object.entries(s.countermeasuresByStatus).map(([k, v]) => [k, String(v)])
  const riskRows = Object.entries(s.risksByLevel).map(([k, v]) => [k, String(v)])

  return [
    h1('2. Executive Summary'),
    spacer(),
    h2('2.1 Summary Metrics'),
    spacer(),
    buildTable(
      [4680, 4680],
      ['Metric', 'Count'],
      [
        ['Total Active Threats', String(s.totalActiveThreats)],
        ['Total Triaged Threats', String(s.totalTriagedThreats)],
        ['Total Countermeasures', String(s.totalCountermeasures)],
        ['Open Gaps', String(s.totalGaps)],
        ['Waived Countermeasures', String(s.totalWaived)],
        ['Inherited Countermeasures', String(s.totalInherited)],
        ['Total Risks', String(s.totalRisks)],
      ],
    ),
    spacer(),
    h2('2.2 Threat Status Breakdown'),
    spacer(),
    buildTable([4680, 4680], ['Status', 'Count'], statusRows),
    spacer(),
    h2('2.3 Countermeasure Status Breakdown'),
    spacer(),
    buildTable([4680, 4680], ['Status', 'Count'], cmRows),
    spacer(),
    ...(riskRows.length > 0
      ? [
          h2('2.4 Risk Level Breakdown') as Paragraph | Table,
          spacer(),
          buildTable([4680, 4680], ['Level', 'Count'], riskRows),
          spacer(),
        ]
      : []),
  ]
}

function buildScopeSection(data: ReportData): (Paragraph | Table)[] {
  const scope = data.scope
  const children: (Paragraph | Table)[] = [
    h1('3. Scope'),
    spacer(),
    h2('3.1 Scope Description'),
    para(scope.description || '—'),
    spacer(),
  ]

  if (scope.assumptions.length > 0) {
    children.push(
      h2('3.2 Assumptions'),
      spacer(),
      buildTable(
        [4500, 1800, 3060],
        ['Assumption', 'Validity', 'Topics'],
        scope.assumptions.map((a) => [
          a.description,
          a.validity,
          a.topics.join(', '),
        ]),
      ),
      spacer(),
    )
  }

  if (scope.outOfScopeItems.length > 0) {
    children.push(
      h2('3.3 Out of Scope'),
      spacer(),
      buildTable(
        [3120, 6240],
        ['Item', 'Reason'],
        scope.outOfScopeItems.map((i) => [i.name, i.reason]),
      ),
      spacer(),
    )
  }

  return children
}

function buildArchitectureSection(data: ReportData, dfdImages: Map<string, Uint8Array>): (Paragraph | Table)[] {
  const arch = data.architecture
  const children: (Paragraph | Table)[] = [h1('4. System Architecture'), spacer()]

  // DFD inventory table
  if (arch.dfds.length > 0) {
    children.push(
      h2('4.1 Data Flow Diagrams'),
      spacer(),
      buildTable(
        [3240, 1800, 720, 720, 2880],
        ['Diagram Name', 'Type', 'Nodes', 'Edges', 'Notes'],
        arch.dfds.map((dfd) => [
          dfd.name,
          dfd.diagramType,
          String(dfd.nodeCount),
          String(dfd.edgeCount),
          dfd.isPrimary ? 'Primary DFD' : 'Reference DFD',
        ]),
      ),
      spacer(),
    )

    // Per-DFD placeholder + node inventory
    arch.dfds.forEach((dfd, idx) => {
      children.push(
        h3(`Figure ${idx + 1}: ${dfd.name}${dfd.isPrimary ? ' (Primary)' : ''}`),
        ...(dfdImages.get(dfd.id)
          ? [new Paragraph({ children: [new ImageRun({ data: dfdImages.get(dfd.id)!, type: 'png', transformation: { width: 600, height: 360 } })] })]
          : [placeholder(`DFD diagram unavailable — ${dfd.name}`)]),
        spacer(),
      )

      // If canvasData has nodes, extract a component inventory
      const nodes = (dfd.canvasData as any)?.nodes
      if (Array.isArray(nodes) && nodes.length > 0) {
        const nodeRows = nodes
          .filter((n: any) => n?.data)
          .map((n: any) => [
            n.data?.label ?? n.data?.name ?? n.id ?? '—',
            n.type ?? '—',
          ])
        if (nodeRows.length > 0) {
          children.push(
            para('Component nodes in this diagram:', { italic: true }),
            buildTable([4680, 4680], ['Node Label', 'Type'], nodeRows),
            spacer(),
          )
        }
      }
    })
  }

  // Trust Zones
  if (arch.trustZones.length > 0) {
    children.push(
      h2('4.2 Trust Zones'),
      spacer(),
      buildTable(
        [2400, 1200, 5760],
        ['Zone Name', 'Trust Level', 'Description'],
        arch.trustZones.map((z) => [z.name, String(z.trustLevel), z.description]),
      ),
      spacer(),
    )
  }

  // Trust Boundaries
  if (arch.trustBoundaries.length > 0) {
    children.push(
      h2('4.3 Trust Boundaries'),
      spacer(),
      buildTable(
        [3120, 3120, 3120],
        ['Boundary', 'Zone A', 'Zone B'],
        arch.trustBoundaries.map((b) => [b.label, b.zoneA, b.zoneB]),
      ),
      spacer(),
    )
  }

  // Reference Images
  if (arch.referenceImages.length > 0) {
    children.push(
      h2('4.4 Reference Images'),
      spacer(),
      buildTable(
        [4680, 4680],
        ['Filename', 'Description'],
        arch.referenceImages.map((img) => [img.filename, img.description]),
      ),
      spacer(),
    )
  }

  return children
}

function buildDataAssetsSection(data: ReportData): (Paragraph | Table)[] {
  return [
    h1('5. Data Assets'),
    spacer(),
    ...(data.dataAssets.length > 0
      ? [buildTable(
          [1800, 1440, 1260, 1260, 1260, 2340],
          ['Name', 'Classification', 'Confidentiality', 'Integrity', 'Availability', 'Description'],
          data.dataAssets.map((a) => [a.name, a.classification, a.confidentiality, a.integrity, a.availability, a.description]),
        ) as Paragraph | Table]
      : [para('No data assets defined.') as Paragraph | Table]),
    spacer(),
  ]
}

function buildComponentsSection(data: ReportData): (Paragraph | Table)[] {
  const c = data.components
  const allComponents = [
    ...c.processes.map((p) => ({ ...p, _type: 'Process' })),
    ...c.dataStores.map((p) => ({ ...p, _type: 'Data Store' })),
    ...c.humanActors.map((p) => ({ ...p, _type: 'Human Actor' })),
    ...c.systemActors.map((p) => ({ ...p, _type: 'System Actor' })),
  ]

  if (allComponents.length === 0 && data.dataFlows.length === 0) return []

  const children: (Paragraph | Table)[] = [
    h1('6. Component Inventory'),
    spacer(),
  ]

  if (allComponents.length > 0) {
    children.push(
      buildTable(
        [2400, 1440, 1440, 1440, 2640],
        ['Name', 'Type', 'Category', 'Trust Zone', 'Description'],
        allComponents.map((c) => {
          const displayType = c._type === 'Human Actor' && c.actorType
            ? `${c._type}\n(${formatActorType(c.actorType)})`
            : c._type
          return [c.name, displayType, c.category, c.trustZone ?? '—', c.description]
        }),
      ),
      spacer(),
    )
  }

  if (data.dataFlows.length > 0) {
    children.push(
      h2('6.1 Data Flows'),
      spacer(),
      buildTable(
        [1800, 1440, 1440, 1260, 1080, 1080, 1260],
        ['Label', 'Source', 'Destination', 'Protocol', 'Encrypted', 'Authenticated', 'Trust Zone Crossing'],
        data.dataFlows.map((flow) => [
          flow.label,
          flow.source ?? '—',
          flow.destination ?? '—',
          flow.protocol || '—',
          flow.encrypted ? 'Yes' : 'No',
          flow.authenticated ? 'Yes' : 'No',
          flow.crossesTrustZone ? 'Yes' : 'No',
        ]),
      ),
      spacer(),
    )
  }

  return children
}

function buildThreatAnalysisSection(data: ReportData): (Paragraph | Table)[] {
  const allThreats = flattenThreats(data)

  const children: (Paragraph | Table)[] = [
    h1('8. Threat Analysis'),
    spacer(),
    ...(allThreats.length > 0
      ? [
          para(`This section documents ${allThreats.length} identified threats across all system components and data flows.`),
          spacer(),
          buildTable(
            [2640, 1800, 1800, 960, 960, 1200],
            ['Threat Name', 'Component / Data Flow', 'Classifications', 'Inherent Severity', 'Status', 'CMs'],
            allThreats.map(({ threat, context }) => [threat.threatName, context, (threat.taxonomyEntries ?? []).map(e => formatTaxonomyEntryLabel(e)).join(', ') || '—', threat.inherentSeverity, threat.status, String(threat.countermeasures.length)]),
          ) as Paragraph | Table,
        ]
      : [para('No active threats defined.') as Paragraph | Table]),
    spacer(),
  ]

  return children
}

function buildStrideSummarySection(data: ReportData): (Paragraph | Table)[] {
  return [
    h1('7. STRIDE Summary'),
    spacer(),
    buildTable(
      [6240, 3120],
      ['STRIDE Category', 'Threats'],
      Object.entries(data.threatAnalysis.strideSummary).map(([category, count]) => [category, String(count)]),
    ),
    spacer(),
  ]
}

function buildTriagedThreatsSection(data: ReportData): (Paragraph | Table)[] {
  const triaged = data.threatAnalysis.triagedThreats
  return [
    h1('9. Triaged Threats'),
    spacer(),
    ...(triaged.length > 0
      ? [buildTable(
          [2400, 2160, 1800, 2880],
          ['Threat Name', 'Component / Data Flow', 'Triage Status', 'Decision Rationale'],
          triaged.map((t) => [t.threatName, t.componentName ?? t.flowLabel ?? '—', t.triageStatus, t.decisionRationale]),
        ) as Paragraph | Table]
      : [para('No triaged threats.') as Paragraph | Table]),
    spacer(),
  ]
}

function buildCountermeasureStatusSection(data: ReportData): (Paragraph | Table)[] {
  const rows = Object.entries(data.countermeasureSummary.statusBreakdown)
    .map(([status, count]) => [status, String(count)])
  return [
    h1('10. Countermeasure Status'),
    spacer(),
    buildTable([6240, 3120], ['Status', 'Count'], rows),
    spacer(),
  ]
}

function buildGapsSection(data: ReportData): (Paragraph | Table)[] {
  const gaps = data.countermeasureSummary.gaps
  return [
    h1('11. Gaps'),
    spacer(),
    ...(gaps.length > 0
      ? [buildTable(
          [2880, 2160, 1440, 2880],
          ['Countermeasure', 'Component / Data Flow', 'Priority', 'Assigned Owner'],
          gaps.map((g) => [g.countermeasureName, g.componentName ?? g.flowLabel ?? '—', g.priority, g.assignedOwnerEmail ?? 'Unassigned']),
        ) as Paragraph | Table]
      : [para('No open gaps.') as Paragraph | Table]),
    spacer(),
  ]
}

function buildWaivedSection(data: ReportData): (Paragraph | Table)[] {
  const waived = data.countermeasureSummary.waived
  return [
    h1('12. Waived Countermeasures'),
    spacer(),
    ...(waived.length > 0
      ? [buildTable(
          [4680, 4680],
          ['Countermeasure', 'Component / Data Flow'],
          waived.map((item) => [item.countermeasureName, item.componentName ?? item.flowLabel ?? '—']),
        ) as Paragraph | Table]
      : [para('No waived countermeasures.') as Paragraph | Table]),
    spacer(),
  ]
}

function buildInheritedSection(data: ReportData): (Paragraph | Table)[] {
  const inherited = data.countermeasureSummary.inherited
  return [
    h1('13. Inherited Countermeasures'),
    spacer(),
    ...(inherited.length > 0
      ? [buildTable(
          [2880, 2160, 4320],
          ['Countermeasure', 'Component', 'Inherited From'],
          inherited.map((item) => [
            item.countermeasureName,
            item.componentName,
            `${item.inheritedFromComponentName} (${item.inheritedFromZoneName})`,
          ]),
        ) as Paragraph | Table]
      : [para('No inherited countermeasures.') as Paragraph | Table]),
    spacer(),
  ]
}

function buildCountermeasuresSection(data: ReportData): (Paragraph | Table)[] {
  const allThreats = flattenThreats(data)
  const rows: string[][] = []

  for (const { threat, context } of allThreats) {
    for (const cm of threat.countermeasures) {
      const standards = (cm.complianceStandards ?? [])
        .map(s => `${s.frameworkName} ${s.sectionCode}`)
        .join(', ') || '—'
      rows.push([
        cm.countermeasureName,
        (cm.controlFunctions || []).join(', '),
        cm.status,
        cm.priority,
        standards,
        threat.threatName,
        context,
      ])
    }
  }

  const children: (Paragraph | Table)[] = [
    h1('14. Countermeasure Detail'),
    spacer(),
    ...(rows.length > 0
      ? [buildTable(
          [1800, 960, 780, 720, 1800, 1440, 1860],
          ['Countermeasure', 'Control Type', 'Status', 'Priority', 'Compliance', 'Associated Threat', 'Component'],
          rows,
        ) as Paragraph | Table]
      : [para('No countermeasures defined.') as Paragraph | Table]),
    spacer(),
  ]

  return children
}

function buildRisksSection(data: ReportData): (Paragraph | Table)[] {
  return [
    h1('15. Risk Register'),
    spacer(),
    ...(data.risks.length > 0
      ? [buildTable(
          [2160, 1200, 1200, 1200, 1200, 2400],
          ['Risk Name', 'Inherent Score', 'Inherent Level', 'Residual Score', 'Residual Level', 'Owner'],
          data.risks.map((r) => [r.name, String(r.inherentScore), r.inherentLevel, String(r.residualScore), r.residualLevel, r.ownerEmail ?? 'Unassigned']),
        ) as Paragraph | Table]
      : [para('No risks defined.') as Paragraph | Table]),
    spacer(),
  ]
}

function buildComplianceSection(data: ReportData): (Paragraph | Table)[] {
  return [
    h1('16. Compliance Mapping'),
    spacer(),
    ...(data.compliance.frameworks.length > 0
      ? [buildTable(
          [3240, 1680, 1680, 2760],
          ['Framework', 'Total Requirements', 'Covered', 'Coverage %'],
          data.compliance.frameworks.map((fw) => [fw.name, String(fw.totalRequirements), String(fw.coveredRequirements), `${fw.coveragePercentage.toFixed(1)}%`]),
        ) as Paragraph | Table]
      : [para('No compliance frameworks linked.') as Paragraph | Table]),
    spacer(),
  ]
}

function buildCrossFrameworkMappingsSection(data: ReportData): (Paragraph | Table)[] {
  const groups = data.compliance.crossFrameworkMappings ?? []
  const children: (Paragraph | Table)[] = [h1('17. Cross-Framework Mappings'), spacer()]

  if (groups.length === 0) {
    children.push(para('No cross-framework requirement mappings available.'), spacer())
    return children
  }

  for (const group of groups) {
    children.push(
      h2(`${group.sourceFramework} → ${group.targetFramework}`),
      spacer(),
      buildTable(
        [1800, 3000, 1800, 2760],
        ['Source', 'Source Description', 'Target', 'Target Description / Sufficiency'],
        group.mappings.map((entry) => [
          entry.fromSectionCode,
          entry.fromDescription,
          entry.toSectionCode,
          `${entry.toDescription}\n${entry.sufficiency}`,
        ]),
      ),
      spacer(),
    )
  }

  return children
}

function buildAssumptionsReviewSection(data: ReportData): (Paragraph | Table)[] {
  const assumptions = data.scope.assumptions
  return [
    h1('18. Assumptions Review'),
    spacer(),
    ...(assumptions.length > 0
      ? [buildTable(
          [4320, 1800, 3240],
          ['Assumption', 'Validity', 'Topics'],
          assumptions.map((assumption) => [assumption.description, assumption.validity, assumption.topics.join(', ') || '—']),
        ) as Paragraph | Table]
      : [para('No assumptions defined.') as Paragraph | Table]),
    spacer(),
  ]
}

function buildFindingsSection(data: ReportData): (Paragraph | Table)[] {
  const findings: string[][] = []
  const exposed = data.summaryMetrics.threatsByStatus.exposed ?? 0
  const criticalGaps = data.countermeasureSummary.gaps.filter((gap) => gap.priority === 'critical')
  const highRisks = data.risks.filter((risk) => risk.residualLevel === 'critical' || risk.residualLevel === 'high')
  const unconfirmed = data.scope.assumptions.filter((assumption) => assumption.validity === 'unconfirmed')

  if (exposed > 0) findings.push(['High', `${exposed} exposed threat${exposed === 1 ? '' : 's'}`, 'Unaddressed countermeasure gaps require attention.'])
  if (criticalGaps.length > 0) findings.push(['Critical', `${criticalGaps.length} critical-priority gap${criticalGaps.length === 1 ? '' : 's'}`, criticalGaps.map((gap) => gap.countermeasureName).join(', ')])
  if (highRisks.length > 0) findings.push(['High', `${highRisks.length} high/critical residual risk${highRisks.length === 1 ? '' : 's'}`, highRisks.map((risk) => risk.name).join(', ')])
  if (unconfirmed.length > 0) findings.push(['Medium', `${unconfirmed.length} unconfirmed assumption${unconfirmed.length === 1 ? '' : 's'}`, 'Confirm or reject assumptions before relying on this model.'])
  if (data.summaryMetrics.totalWaived > 0) findings.push(['Info', `${data.summaryMetrics.totalWaived} waived countermeasure${data.summaryMetrics.totalWaived === 1 ? '' : 's'}`, 'Risk has been accepted for these countermeasures.'])
  if (findings.length === 0) findings.push(['Info', 'No significant findings', 'No critical or high-priority findings were derived from the report data.'])

  return [
    h1('19. Findings & Action Items'),
    spacer(),
    buildTable([1080, 3240, 5040], ['Severity', 'Finding', 'Detail'], findings),
    spacer(),
  ]
}

function buildProgressSection(data: ReportData): (Paragraph | Table)[] {
  const checklistRows = data.progressChecklist.map((item) => [
    item.checked ? 'Complete' : 'Incomplete',
    item.label,
    item.autoComputed ? 'Automatic' : 'Manual',
  ])
  const children: (Paragraph | Table)[] = [h1('20. Completion Status'), spacer()]

  if (checklistRows.length > 0) {
    children.push(
      buildTable([1440, 5760, 2160], ['Status', 'Checklist Item', 'Source'], checklistRows),
      spacer(),
    )
  }

  if (data.completionStatus) {
    children.push(h2('20.1 Completion Cross-Check'), spacer())
    for (const item of data.completionStatus.systemDefinition) {
      children.push(para(`${item.checked ? 'Complete' : 'Incomplete'} — ${item.label} (${item.countLabel})`))
    }
    for (const item of data.completionStatus.coverage) {
      children.push(para(`${item.label}: ${item.numerator}/${item.denominator} (${item.percentage}%)`))
    }
    children.push(spacer())
  }

  if (checklistRows.length === 0 && !data.completionStatus) children.push(para('No completion data available.'), spacer())
  return children
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function exportWordDoc(
  data: ReportData,
  modelName: string,
  dfdImages: Map<string, Uint8Array>,
): Promise<void> {
  const children: (Paragraph | Table)[] = [
    // Title page
    new Paragraph({
      heading: HeadingLevel.TITLE,
      children: [new TextRun({ text: modelName })],
    }),
    new Paragraph({
      children: [
        new TextRun({
          text: 'Cybersecurity Threat Model — Full Report',
          size: 28,
          color: '444444',
        }),
      ],
    }),
    new Paragraph({
      children: [
        new TextRun({
          text: `Generated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}`,
          size: 24,
          color: '888888',
        }),
      ],
    }),
    spacer(),
    placeholder('This document is auto-generated. Review all sections before submission.'),
    pageBreak(),

    // Sections
    ...buildMetadataSection(data),
    pageBreak(),
    ...buildSummarySection(data),
    pageBreak(),
    ...buildScopeSection(data),
    pageBreak(),
    ...buildArchitectureSection(data, dfdImages),
    pageBreak(),
    ...buildDataAssetsSection(data),
    pageBreak(),
    ...buildComponentsSection(data),
    pageBreak(),
    ...buildStrideSummarySection(data),
    pageBreak(),
    ...buildThreatAnalysisSection(data),
    pageBreak(),
    ...buildTriagedThreatsSection(data),
    pageBreak(),
    ...buildCountermeasureStatusSection(data),
    pageBreak(),
    ...buildGapsSection(data),
    pageBreak(),
    ...buildWaivedSection(data),
    pageBreak(),
    ...buildInheritedSection(data),
    pageBreak(),
    ...buildCountermeasuresSection(data),
    pageBreak(),
    ...buildRisksSection(data),
    pageBreak(),
    ...buildComplianceSection(data),
    pageBreak(),
    ...buildCrossFrameworkMappingsSection(data),
    pageBreak(),
    ...buildAssumptionsReviewSection(data),
    pageBreak(),
    ...buildFindingsSection(data),
    pageBreak(),
    ...buildProgressSection(data),
  ]

  const doc = new Document({
    styles: createDocumentStyles(),
    numbering: createNumberingConfig(),
    sections: [
      {
        properties: createPageProperties(),
        children,
      },
    ],
  })

  await downloadDocx(doc, `${slugify(modelName)}-threat-model-report.docx`)
}
