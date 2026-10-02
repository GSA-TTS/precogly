export const CONTROL_FUNCTIONS = [
  { value: 'preventive' as const, label: 'Preventive' },
  { value: 'detective' as const, label: 'Detective' },
  { value: 'corrective' as const, label: 'Corrective' },
  { value: 'deterrent' as const, label: 'Deterrent' },
  { value: 'recovery' as const, label: 'Recovery' },
  { value: 'compensating' as const, label: 'Compensating' },
] as const

export type ControlFunction = (typeof CONTROL_FUNCTIONS)[number]['value']

export const CONTROL_NATURES = [
  { value: 'technical' as const, label: 'Technical' },
  { value: 'administrative' as const, label: 'Administrative' },
  { value: 'physical' as const, label: 'Physical' },
] as const

export type ControlNature = (typeof CONTROL_NATURES)[number]['value']
