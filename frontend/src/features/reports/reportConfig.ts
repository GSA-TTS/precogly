import type { ReportType } from '@/features/reports/types/report'

export type SectionDepth = 'full' | 'summary' | 'flagged' | 'top3' | 'count' | 'critical' | 'compliance'

export interface SectionConfig {
  id: string
  title: string
  depth: SectionDepth
}

const SECTION_MAP: Record<ReportType, SectionConfig[]> = {
  executive: [
    { id: 'executiveSummary', title: 'Executive Summary', depth: 'full' },
    { id: 'scope', title: 'Scope & Assumptions', depth: 'summary' },
    { id: 'strideSummary', title: 'STRIDE Summary', depth: 'full' },
    { id: 'countermeasureStatus', title: 'Countermeasure Status', depth: 'full' },
    { id: 'gaps', title: 'Top Gaps', depth: 'top3' },
    { id: 'waived', title: 'Waived Countermeasures', depth: 'count' },
    { id: 'risks', title: 'Risk Register', depth: 'full' },
    { id: 'compliance', title: 'Compliance Coverage', depth: 'summary' },
    { id: 'assumptions', title: 'Assumptions Review', depth: 'flagged' },
    { id: 'findings', title: 'Key Findings', depth: 'critical' },
  ],
  technical: [
    { id: 'scope', title: 'Scope & Assumptions', depth: 'summary' },
    { id: 'architecture', title: 'Architecture', depth: 'full' },
    { id: 'dataAssets', title: 'Data Assets', depth: 'full' },
    { id: 'components', title: 'Components & Data Flows', depth: 'full' },
    { id: 'strideSummary', title: 'STRIDE Summary', depth: 'full' },
    { id: 'threatDetail', title: 'Threat Detail', depth: 'full' },
    { id: 'triagedThreats', title: 'Triaged Threats', depth: 'full' },
    { id: 'countermeasureStatus', title: 'Countermeasure Status', depth: 'full' },
    { id: 'gaps', title: 'Gaps', depth: 'full' },
    { id: 'waived', title: 'Waived Countermeasures', depth: 'full' },
    { id: 'inherited', title: 'Inherited Countermeasures', depth: 'full' },
    { id: 'risks', title: 'Risk Register', depth: 'summary' },
    { id: 'findings', title: 'Findings & Action Items', depth: 'full' },
  ],
  compliance: [
    { id: 'scope', title: 'Scope & Assumptions', depth: 'full' },
    { id: 'dataAssets', title: 'Data Assets', depth: 'summary' },
    { id: 'strideSummary', title: 'STRIDE Summary', depth: 'summary' },
    { id: 'triagedThreats', title: 'Triaged Threats', depth: 'full' },
    { id: 'countermeasureStatus', title: 'Countermeasure Status', depth: 'full' },
    { id: 'gaps', title: 'Gaps', depth: 'full' },
    { id: 'waived', title: 'Waived Countermeasures', depth: 'full' },
    { id: 'risks', title: 'Risk Register', depth: 'full' },
    { id: 'compliance', title: 'Compliance Mapping', depth: 'full' },
    { id: 'crossFrameworkMappings', title: 'Cross-Framework Mappings', depth: 'full' },
    { id: 'assumptions', title: 'Assumptions Review', depth: 'full' },
    { id: 'findings', title: 'Compliance Findings', depth: 'compliance' },
    { id: 'progressChecklist', title: 'Completion Status', depth: 'full' },
  ],
  full: [
    { id: 'executiveSummary', title: 'Executive Summary', depth: 'full' },
    { id: 'scope', title: 'Scope & Assumptions', depth: 'full' },
    { id: 'architecture', title: 'Architecture', depth: 'full' },
    { id: 'dataAssets', title: 'Data Assets', depth: 'full' },
    { id: 'components', title: 'Components & Data Flows', depth: 'full' },
    { id: 'strideSummary', title: 'STRIDE Summary', depth: 'full' },
    { id: 'threatDetail', title: 'Threat Detail', depth: 'full' },
    { id: 'triagedThreats', title: 'Triaged Threats', depth: 'full' },
    { id: 'countermeasureStatus', title: 'Countermeasure Status', depth: 'full' },
    { id: 'gaps', title: 'Gaps', depth: 'full' },
    { id: 'waived', title: 'Waived Countermeasures', depth: 'full' },
    { id: 'inherited', title: 'Inherited Countermeasures', depth: 'full' },
    { id: 'risks', title: 'Risk Register', depth: 'full' },
    { id: 'compliance', title: 'Compliance Mapping', depth: 'full' },
    { id: 'crossFrameworkMappings', title: 'Cross-Framework Mappings', depth: 'full' },
    { id: 'assumptions', title: 'Assumptions Review', depth: 'full' },
    { id: 'findings', title: 'Findings & Action Items', depth: 'full' },
    { id: 'progressChecklist', title: 'Completion Status', depth: 'full' },
  ],
}

export function getSectionsForType(reportType: ReportType): SectionConfig[] {
  return SECTION_MAP[reportType]
}
