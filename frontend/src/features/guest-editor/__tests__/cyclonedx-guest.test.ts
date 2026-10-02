import { describe, it, expect } from 'vitest'
import {
  serializeGuestToCycloneDx,
  deserializeCycloneDxToGuest,
} from '../lib/cyclonedx-guest'
import type { DiagramNode, DiagramEdge } from '@/features/dfd-editor/types'
import type {
  GuestThreat,
  GuestCountermeasure,
  GuestSystemContext,
} from '../types'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeNode(
  id: string,
  type: string,
  label: string,
  overrides: Record<string, unknown> = {}
): DiagramNode {
  return {
    id,
    type,
    position: { x: 0, y: 0 },
    data: { label, ...overrides },
  } as DiagramNode
}

function makeEdge(
  id: string,
  source: string,
  target: string,
  label = ''
): DiagramEdge {
  return {
    id,
    type: 'dataFlow',
    source,
    target,
    data: { label, encrypted: false, authenticated: false },
  } as DiagramEdge
}

function makeThreat(overrides: Partial<GuestThreat> & { name: string; targetId: string }): GuestThreat {
  return {
    id: `threat-${overrides.name.toLowerCase().replace(/\s+/g, '-')}`,
    targetType: 'component',
    description: '',
    severity: 'medium',
    status: 'open',
    createdAt: new Date().toISOString(),
    ...overrides,
  }
}

function makeCountermeasure(
  overrides: Partial<GuestCountermeasure> & { name: string; threatId: string }
): GuestCountermeasure {
  return {
    id: `cm-${overrides.name.toLowerCase().replace(/\s+/g, '-')}`,
    description: '',
    controlFunction: ['preventive'],
    controlNature: 'technical',
    createdAt: new Date().toISOString(),
    ...overrides,
  }
}

function roundtrip(
  nodes: DiagramNode[],
  edges: DiagramEdge[],
  threats: GuestThreat[],
  countermeasures: GuestCountermeasure[] = [],
  systemContext?: GuestSystemContext
) {
  const json = serializeGuestToCycloneDx(
    'Test Diagram',
    nodes,
    edges,
    threats,
    countermeasures,
    'yourdon',
    systemContext
  )
  return deserializeCycloneDxToGuest(json)
}

// ---------------------------------------------------------------------------
// 1. Basic roundtrip
// ---------------------------------------------------------------------------

describe('basic roundtrip', () => {
  it('preserves nodes, edges, threats, countermeasures, and system context', () => {
    const nodes = [
      makeNode('p1', 'process', 'Web Server'),
      makeNode('ds1', 'datastore', 'User DB'),
    ]
    const edges = [makeEdge('e1', 'p1', 'ds1', 'Query')]
    const threats = [
      makeThreat({ name: 'SQL Injection', targetId: 'p1' }),
    ]
    const countermeasures = [
      makeCountermeasure({
        name: 'Input Validation',
        threatId: threats[0].id,
        controlFunction: ['preventive', 'detective'],
        controlNature: 'technical',
      }),
    ]
    const systemContext: GuestSystemContext = {
      session: { facilitator: 'Alice', participants: ['Bob'], meetingDate: '2026-01-15' },
      systemInfo: { description: 'E-commerce platform', criticality: 'high' },
      dataAssets: [
        {
          id: 'da-1',
          name: 'User PII',
          description: 'Personal data',
          classification: 'confidential',
          confidentiality: 'high',
          integrity: 'high',
          availability: 'medium',
          complianceTags: ['GDPR'],
          dataSensitivity: ['pii'],
        },
      ],
      assumptions: [
        { id: 'a-1', description: 'TLS everywhere', validity: 'confirmed', topics: ['network'] },
      ],
      outOfScopeItems: [
        { id: 'oos-1', name: 'Physical access', reason: 'Handled by facilities team' },
      ],
    }

    const result = roundtrip(nodes, edges, threats, countermeasures, systemContext)

    // Nodes
    expect(result.nodes).toHaveLength(2)
    expect(result.nodes.map((n) => n.data.label)).toEqual(['Web Server', 'User DB'])
    expect(result.nodes.map((n) => n.type)).toEqual(['process', 'datastore'])

    // Edges
    expect(result.edges).toHaveLength(1)
    expect((result.edges[0].data as Record<string, unknown>).label).toBe('Query')

    // Threats
    expect(result.threats).toHaveLength(1)
    expect(result.threats[0].name).toBe('SQL Injection')
    expect(result.threats[0].targetId).toBe('p1')
    expect(result.threats[0].targetType).toBe('component')

    // Countermeasures
    expect(result.countermeasures).toHaveLength(1)
    expect(result.countermeasures[0].name).toBe('Input Validation')
    expect(result.countermeasures[0].controlFunction).toEqual(['preventive', 'detective'])
    expect(result.countermeasures[0].controlNature).toBe('technical')
    expect(result.countermeasures[0].threatId).toBe(result.threats[0].id)

    // System context
    expect(result.systemContext).toBeDefined()
    expect(result.systemContext!.session.facilitator).toBe('Alice')
    expect(result.systemContext!.systemInfo.criticality).toBe('high')
    expect(result.systemContext!.dataAssets).toHaveLength(1)
    expect(result.systemContext!.dataAssets[0].name).toBe('User PII')
    expect(result.systemContext!.assumptions).toHaveLength(1)
  })

  it('preserves notation style', () => {
    const result = roundtrip([], [], [])
    expect(result.notationStyle).toBe('yourdon')
  })
})

// ---------------------------------------------------------------------------
// 2. Duplicate node names
// ---------------------------------------------------------------------------

describe('duplicate node names', () => {
  it('maps threats to correct nodes when two processes share the same name', () => {
    const nodes = [
      makeNode('p1', 'process', 'API Gateway'),
      makeNode('p2', 'process', 'API Gateway'),
    ]
    const threats = [
      makeThreat({ name: 'Auth Bypass', targetId: 'p1' }),
      makeThreat({ name: 'Rate Limit Evasion', targetId: 'p2' }),
    ]

    const result = roundtrip(nodes, [], threats)

    expect(result.threats).toHaveLength(2)

    const authBypass = result.threats.find((t) => t.name === 'Auth Bypass')!
    const rateLimitEvasion = result.threats.find((t) => t.name === 'Rate Limit Evasion')!

    // Each threat must be on a different node
    expect(authBypass.targetId).not.toBe('')
    expect(rateLimitEvasion.targetId).not.toBe('')
    expect(authBypass.targetId).not.toBe(rateLimitEvasion.targetId)
  })

  it('maps threats to correct nodes when different types share the same name', () => {
    const nodes = [
      makeNode('p1', 'process', 'Payments'),
      makeNode('ds1', 'datastore', 'Payments'),
    ]
    const threats = [
      makeThreat({ name: 'Code Injection', targetId: 'p1' }),
      makeThreat({ name: 'Data Leak', targetId: 'ds1' }),
    ]

    const result = roundtrip(nodes, [], threats)

    const codeInjection = result.threats.find((t) => t.name === 'Code Injection')!
    const dataLeak = result.threats.find((t) => t.name === 'Data Leak')!

    expect(codeInjection.targetId).toBe('p1')
    expect(codeInjection.targetType).toBe('component')
    expect(dataLeak.targetId).toBe('ds1')
    expect(dataLeak.targetType).toBe('component')
  })
})

// ---------------------------------------------------------------------------
// 3. Multiple same-pair flows
// ---------------------------------------------------------------------------

describe('multiple same-pair flows', () => {
  it('maps threats to correct edges when two flows connect the same nodes', () => {
    const nodes = [
      makeNode('p1', 'process', 'Browser'),
      makeNode('p2', 'process', 'API Server'),
    ]
    const edges = [
      makeEdge('e1', 'p1', 'p2', 'Login Request'),
      makeEdge('e2', 'p1', 'p2', 'Upload File'),
    ]
    const threats = [
      makeThreat({ name: 'Credential Stuffing', targetId: 'e1', targetType: 'dataflow' }),
      makeThreat({ name: 'Malware Upload', targetId: 'e2', targetType: 'dataflow' }),
    ]

    const result = roundtrip(nodes, edges, threats)

    expect(result.threats).toHaveLength(2)

    const credStuffing = result.threats.find((t) => t.name === 'Credential Stuffing')!
    const malwareUpload = result.threats.find((t) => t.name === 'Malware Upload')!

    // Each threat must be on a different edge
    expect(credStuffing.targetId).not.toBe('')
    expect(malwareUpload.targetId).not.toBe('')
    expect(credStuffing.targetId).not.toBe(malwareUpload.targetId)
    expect(credStuffing.targetType).toBe('dataflow')
    expect(malwareUpload.targetType).toBe('dataflow')
  })

  it('handles duplicate names + multiple flows combined', () => {
    const nodes = [
      makeNode('p1', 'process', 'Service'),
      makeNode('p2', 'process', 'Service'),
    ]
    const edges = [
      makeEdge('e1', 'p1', 'p2', 'Heartbeat'),
      makeEdge('e2', 'p1', 'p2', 'Data Sync'),
    ]
    const threats = [
      makeThreat({ name: 'Spoofed Heartbeat', targetId: 'e1', targetType: 'dataflow' }),
      makeThreat({ name: 'Data Tampering', targetId: 'e2', targetType: 'dataflow' }),
    ]

    const result = roundtrip(nodes, edges, threats)

    const spoofed = result.threats.find((t) => t.name === 'Spoofed Heartbeat')!
    const tampering = result.threats.find((t) => t.name === 'Data Tampering')!

    expect(spoofed.targetId).not.toBe('')
    expect(tampering.targetId).not.toBe('')
    expect(spoofed.targetId).not.toBe(tampering.targetId)
  })
})

// ---------------------------------------------------------------------------
// 4. Backend export import (snake_case normalization)
// ---------------------------------------------------------------------------

describe('backend export import', () => {
  it('normalizes snake_case visualization keys to camelCase', () => {
    const backendExport = {
      specFormat: 'CycloneDX',
      specVersion: '2.0',
      serialNumber: 'urn:uuid:test',
      version: 1,
      metadata: { timestamp: '2026-01-01T00:00:00Z' },
      blueprints: [
        {
          'bom-ref': 'bp-1',
          name: 'Test',
          modelTypes: ['data-flow'],
          assets: [
            { 'bom-ref': 'asset-web-server-1', name: 'Web Server', type: 'component' },
          ],
          visualizations: [
            {
              type: 'precogly-dfd',
              name: 'Test',
              data: {
                nodes: [
                  {
                    id: 'p1',
                    type: 'process',
                    position: { x: 100, y: 200 },
                    data: {
                      label: 'Web Server',
                      technology: 'nginx',
                      is_newly_inserted: false,
                      is_inline_editing: false,
                      data_store_type: 'sql',
                      data_sensitivity: 'confidential',
                    },
                    style: { width: 100, height: 100 },
                  },
                ],
                edges: [],
                notation_style: 'yourdon',
                system_context: {
                  session: { facilitator: '', participants: [], meeting_date: '' },
                  system_info: { description: 'Test system', criticality: 'high' },
                  data_assets: [],
                  assumptions: [],
                  out_of_scope_items: [],
                },
              },
            },
          ],
        },
      ],
      threats: {
        threats: [
          {
            'bom-ref': 'threat-1',
            name: 'Test Threat',
            description: 'desc',
            affectedAssets: ['asset-web-server-1'],
          },
        ],
        scenarios: [
          {
            'bom-ref': 'scenario-1',
            threat: 'threat-1',
            affectedAssets: ['asset-web-server-1'],
            riskScore: { level: 'high' },
          },
        ],
      },
    }

    const result = deserializeCycloneDxToGuest(JSON.stringify(backendExport))

    // Node data keys should be camelCase
    const nodeData = result.nodes[0].data as Record<string, unknown>
    expect(nodeData.label).toBe('Web Server')
    expect(nodeData.technology).toBe('nginx')
    expect(nodeData.dataStoreType).toBe('sql')
    expect(nodeData.dataSensitivity).toBe('confidential')
    // snake_case originals should not exist
    expect(nodeData.data_store_type).toBeUndefined()
    expect(nodeData.data_sensitivity).toBeUndefined()

    // Notation style should be camelCase
    expect(result.notationStyle).toBe('yourdon')

    // System context keys should be camelCase
    expect(result.systemContext).toBeDefined()
    expect(result.systemContext!.systemInfo.description).toBe('Test system')

    // Threat should resolve to the correct node
    expect(result.threats).toHaveLength(1)
    expect(result.threats[0].targetId).toBe('p1')
    expect(result.threats[0].severity).toBe('high')
  })

  it('reads triage status from scenario properties (new format)', () => {
    const doc = {
      specFormat: 'CycloneDX',
      specVersion: '2.0',
      serialNumber: 'urn:uuid:test',
      version: 1,
      metadata: { timestamp: '2026-01-01T00:00:00Z' },
      blueprints: [
        {
          'bom-ref': 'bp-1',
          name: 'Test',
          modelTypes: ['data-flow'],
          assets: [{ 'bom-ref': 'asset-1', name: 'Server', type: 'component' }],
          visualizations: [
            {
              type: 'precogly-dfd',
              name: 'Test',
              data: {
                nodes: [{ id: 'p1', type: 'process', position: { x: 0, y: 0 }, data: { label: 'Server' } }],
                edges: [],
              },
            },
          ],
        },
      ],
      threats: {
        threats: [{ 'bom-ref': 'threat-1', name: 'Threat', description: '', affectedAssets: ['asset-1'] }],
        scenarios: [
          {
            'bom-ref': 'scenario-1',
            threat: 'threat-1',
            affectedAssets: ['asset-1'],
            riskScore: { level: 'medium' },
            properties: [
              { name: 'precogly:threat-status', value: 'accept' },
              { name: 'precogly:decision-rationale', value: 'Risk is tolerable' },
            ],
          },
        ],
      },
    }

    const result = deserializeCycloneDxToGuest(JSON.stringify(doc))
    expect(result.threats[0].status).toBe('accept')
    expect(result.threats[0].decisionRationale).toBe('Risk is tolerable')
  })

  it('falls back to abstract threat properties for old format files', () => {
    const doc = {
      specFormat: 'CycloneDX',
      specVersion: '2.0',
      serialNumber: 'urn:uuid:test',
      version: 1,
      metadata: { timestamp: '2026-01-01T00:00:00Z' },
      blueprints: [
        {
          'bom-ref': 'bp-1',
          name: 'Test',
          modelTypes: ['data-flow'],
          assets: [{ 'bom-ref': 'asset-1', name: 'Server', type: 'component' }],
          visualizations: [
            {
              type: 'precogly-dfd',
              name: 'Test',
              data: {
                nodes: [{ id: 'p1', type: 'process', position: { x: 0, y: 0 }, data: { label: 'Server' } }],
                edges: [],
              },
            },
          ],
        },
      ],
      threats: {
        threats: [
          {
            'bom-ref': 'threat-1',
            name: 'Threat',
            description: '',
            affectedAssets: ['asset-1'],
            properties: [
              { name: 'precogly:threat-status', value: 'eliminate' },
              { name: 'precogly:decision-rationale', value: 'Removed the feature' },
            ],
          },
        ],
        scenarios: [
          {
            'bom-ref': 'scenario-1',
            threat: 'threat-1',
            affectedAssets: ['asset-1'],
            riskScore: { level: 'medium' },
          },
        ],
      },
    }

    const result = deserializeCycloneDxToGuest(JSON.stringify(doc))
    expect(result.threats[0].status).toBe('eliminate')
    expect(result.threats[0].decisionRationale).toBe('Removed the feature')
  })
})

// ---------------------------------------------------------------------------
// 5. Error handling
// ---------------------------------------------------------------------------

describe('error handling', () => {
  it('rejects invalid JSON', () => {
    expect(() => deserializeCycloneDxToGuest('not json {')).toThrow(
      'Could not parse file as JSON'
    )
  })

  it('rejects non-object JSON', () => {
    expect(() => deserializeCycloneDxToGuest('"just a string"')).toThrow(
      'The file content must be a JSON object'
    )
  })

  it('rejects missing specFormat', () => {
    expect(() => deserializeCycloneDxToGuest('{"version": 1}')).toThrow(
      "must have a 'specFormat' field"
    )
  })

  it('rejects wrong specFormat', () => {
    expect(() =>
      deserializeCycloneDxToGuest(JSON.stringify({ specFormat: 'SPDX', specVersion: '2.0' }))
    ).toThrow("Found specFormat 'SPDX' but expected 'CycloneDX'")
  })

  it('rejects unsupported version', () => {
    expect(() =>
      deserializeCycloneDxToGuest(JSON.stringify({ specFormat: 'CycloneDX', specVersion: '1.5' }))
    ).toThrow("Unsupported CycloneDX version '1.5'")
  })

  it('handles missing version gracefully', () => {
    expect(() =>
      deserializeCycloneDxToGuest(JSON.stringify({ specFormat: 'CycloneDX' }))
    ).toThrow("Unsupported CycloneDX version 'unknown'")
  })
})
