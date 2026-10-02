export const TRIAGE_STATUSES = [
  { value: 'open' as const, label: 'Open', description: 'Not yet triaged' },
  { value: 'accept' as const, label: 'Accept', description: 'Risk is tolerable' },
  { value: 'mitigate' as const, label: 'Mitigate', description: 'Reduce risk with countermeasures' },
  { value: 'delegate' as const, label: 'Delegate', description: 'Transfer risk to another party' },
  { value: 'eliminate' as const, label: 'Eliminate', description: 'Remove the threat source entirely' },
] as const

export type TriageStatus = (typeof TRIAGE_STATUSES)[number]['value']

export const ACTIVE_TRIAGE_STATUSES: TriageStatus[] = ['open', 'mitigate']

export function isActiveThreat(status: TriageStatus): boolean {
  return ACTIVE_TRIAGE_STATUSES.includes(status)
}

export const RATIONALE_REQUIRED_STATUSES: TriageStatus[] = ['accept', 'delegate', 'eliminate']

export const TRIAGE_STATUS_COLORS: Record<TriageStatus, string> = {
  open: 'bg-gray-100 text-gray-800',
  accept: 'bg-yellow-100 text-yellow-800',
  mitigate: 'bg-green-100 text-green-800',
  delegate: 'bg-purple-100 text-purple-800',
  eliminate: 'bg-blue-100 text-blue-800',
}
