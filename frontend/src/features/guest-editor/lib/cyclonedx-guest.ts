/**
 * CycloneDX 2.0 TM-BOM serializer/deserializer for the guest editor.
 * Replaces precogly-file.ts with CycloneDX format support.
 */

import type { DiagramNode, DiagramEdge } from '@/features/dfd-editor/types'
import type { DFDNotationStyle } from '@/features/dfd-editor/types/notation'
import type { STRIDECategory } from '@/types/domain'
import type {
  GuestThreat,
  GuestCountermeasure,
  GuestSystemContext,
  GuestDataAsset,
  GuestAssumption,
  ThreatStatus,
  ControlFunction,
  ControlNature,
} from '../types'
import type {
  CycloneDxDocument,
  CycloneDxBlueprint,
  CycloneDxAsset,
  CycloneDxFlow,
  CycloneDxZone,
  CycloneDxBoundary,
  CycloneDxControl,
  CycloneDxThreat,
  CycloneDxScenario,
  CycloneDxVisualization,
  CycloneDxDataSet,
  CycloneDxAssumption,
  CycloneDxProperty,
} from './cyclonedx-types'
import {
  NODE_TYPE_TO_ASSET_TYPE,
  ASSET_TYPE_TO_NODE_TYPE,
  SEVERITY_TO_CDX_RISK_LEVEL,
  CDX_RISK_LEVEL_TO_SEVERITY,
} from './cyclonedx-enum-maps'

// ---------------------------------------------------------------------------
// BomRefGenerator — simple slugified bom-ref generator matching backend pattern
// ---------------------------------------------------------------------------

class BomRefGenerator {
  private counter = new Map<string, number>()

  generate(entityType: string, name: string): string {
    const slug = name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 40) || entityType
    const count = (this.counter.get(entityType) ?? 0) + 1
    this.counter.set(entityType, count)
    return `${entityType}-${slug}-${count}`
  }
}

// ---------------------------------------------------------------------------
// Deserialization result (shared interface)
// ---------------------------------------------------------------------------

export interface DeserializedFile {
  title: string
  nodes: DiagramNode[]
  edges: DiagramEdge[]
  threats: GuestThreat[]
  countermeasures: GuestCountermeasure[]
  notationStyle?: DFDNotationStyle
  systemContext?: GuestSystemContext
}

// ---------------------------------------------------------------------------
// Serialization: Guest editor state -> CycloneDX 2.0 JSON
// ---------------------------------------------------------------------------

export function serializeGuestToCycloneDx(
  title: string,
  nodes: DiagramNode[],
  edges: DiagramEdge[],
  threats: GuestThreat[],
  countermeasures: GuestCountermeasure[],
  notationStyle?: DFDNotationStyle,
  systemContext?: GuestSystemContext
): string {
  const refGen = new BomRefGenerator()
  const nodeIdToBomRef = new Map<string, string>()
  const edgeIdToBomRef = new Map<string, string>()
  const threatIdToBomRef = new Map<string, string>()

  // Build node map for lookups
  const nodeMap = new Map<string, DiagramNode>()
  for (const node of nodes) {
    nodeMap.set(node.id, node)
  }

  // --- Build zones from trustZone nodes ---
  const zoneNodes = nodes.filter((n) => n.type === 'trustZone')
  const zones: CycloneDxZone[] = zoneNodes.map((n) => {
    const bomRef = refGen.generate('zone', n.data.label || 'zone')
    nodeIdToBomRef.set(n.id, bomRef)
    const zone: CycloneDxZone = {
      'bom-ref': bomRef,
      name: n.data.label || '',
      type: 'trust',
    }
    if (n.data.description) zone.description = n.data.description
    const trustLevel = (n.data as Record<string, unknown>).trustLevel as number | undefined
    if (trustLevel != null) zone.trustLevel = trustLevel
    return zone
  })

  // --- Build assets from process/datastore/humanActor/systemActor nodes ---
  const assetNodeTypes = ['process', 'datastore', 'humanActor', 'systemActor']
  const assetNodes = nodes.filter((n) => assetNodeTypes.includes(n.type ?? ''))
  const assets: CycloneDxAsset[] = assetNodes.map((n) => {
    const bomRef = refGen.generate('asset', n.data.label || n.type || 'asset')
    nodeIdToBomRef.set(n.id, bomRef)
    const assetType = NODE_TYPE_TO_ASSET_TYPE[n.type ?? ''] ?? 'component'
    const asset: CycloneDxAsset = {
      'bom-ref': bomRef,
      name: n.data.label || '',
      type: assetType,
    }
    if (n.data.description) asset.description = n.data.description
    // Set zone reference if node is inside a trust zone
    if (n.parentId) {
      const parent = nodeMap.get(n.parentId)
      if (parent?.type === 'trustZone') {
        const zoneRef = nodeIdToBomRef.get(n.parentId)
        if (zoneRef) asset.zone = zoneRef
      }
    }
    return asset
  })

  // --- Build flows from dataFlow edges ---
  const dataFlowEdges = edges.filter((e) => e.type === 'dataFlow')
  const flows: CycloneDxFlow[] = dataFlowEdges.map((e) => {
    const data = e.data as Record<string, unknown> | undefined
    const bomRef = refGen.generate('flow', (data?.label as string) || 'flow')
    edgeIdToBomRef.set(e.id, bomRef)
    const sourceRef = nodeIdToBomRef.get(e.source) ?? e.source
    const destRef = nodeIdToBomRef.get(e.target) ?? e.target
    const flow: CycloneDxFlow = {
      'bom-ref': bomRef,
      source: sourceRef,
      destination: destRef,
      type: 'data',
    }
    if (data?.label) flow.name = data.label as string
    if (data?.description) flow.description = data.description as string
    if (data?.protocol) flow.protocols = [data.protocol as string]
    if (data?.encrypted) flow.encrypted = true
    if (data?.authenticated) flow.authenticated = true
    return flow
  })

  // --- Build boundaries from trustBoundary edges ---
  const trustBoundaryEdges = edges.filter((e) => e.type === 'trustBoundary')
  const boundaries: CycloneDxBoundary[] = trustBoundaryEdges.map((e) => {
    const sourceRef = nodeIdToBomRef.get(e.source) ?? e.source
    const destRef = nodeIdToBomRef.get(e.target) ?? e.target
    const boundary: CycloneDxBoundary = {
      zones: [sourceRef, destRef],
    }
    if (e.data?.label) boundary.name = e.data.label as string
    return boundary
  })

  // --- Build dataSets from systemContext.dataAssets ---
  const dataSets: CycloneDxDataSet[] = (systemContext?.dataAssets ?? []).map(
    (da: GuestDataAsset) => {
      const bomRef = refGen.generate('dataset', da.name || 'dataset')
      const dataSet: CycloneDxDataSet = {
        'bom-ref': bomRef,
        name: da.name,
      }
      if (da.description) dataSet.description = da.description
      if (da.classification) dataSet.classification = da.classification
      return dataSet
    }
  )

  // --- Build assumptions from systemContext.assumptions ---
  const assumptions: CycloneDxAssumption[] = (
    systemContext?.assumptions ?? []
  ).map((a: GuestAssumption) => {
    const assumption: CycloneDxAssumption = {
      'bom-ref': a.id,
      description: a.description,
    }
    if (a.validity) assumption.validity = a.validity
    if (a.topics?.length) assumption.topic = a.topics[0]
    return assumption
  })

  // --- Build visualization with raw canvas data for lossless round-trip ---
  // Strip transient UI flags before persisting
  const cleanedNodes = nodes.map((node) => {
    const { isInlineEditing, isNewlyInserted, ...restData } = node.data as Record<string, unknown>
    const { extent, ...nodeWithoutExtent } = node as Record<string, unknown>
    const base = extent ? nodeWithoutExtent : node
    return isInlineEditing || isNewlyInserted
      ? { ...base, data: restData }
      : base
  })
  const visualization: CycloneDxVisualization = {
    type: 'precogly-dfd',
    name: title,
    data: {
      nodes: cleanedNodes as unknown as Record<string, unknown>[],
      edges: edges as unknown as Record<string, unknown>[],
      notationStyle,
      systemContext,
    },
  }

  // --- Assemble blueprint ---
  const blueprint: CycloneDxBlueprint = {
    'bom-ref': refGen.generate('blueprint', title),
    name: title,
    modelTypes: ['data-flow'],
  }
  if (systemContext?.systemInfo.description) {
    blueprint.description = systemContext.systemInfo.description
  }
  if (zones.length) blueprint.zones = zones
  if (assets.length) blueprint.assets = assets
  if (flows.length) blueprint.flows = flows
  if (boundaries.length) blueprint.boundaries = boundaries
  if (dataSets.length) blueprint.dataSets = dataSets
  if (assumptions.length) blueprint.assumptions = assumptions
  blueprint.visualizations = [visualization]

  // --- Build controls from countermeasures ---
  // Map countermeasure ID → control object for direct lookup (avoids name collisions)
  const countermeasureIdToControl = new Map<string, CycloneDxControl>()
  const controls: CycloneDxControl[] = countermeasures.map((c) => {
    const bomRef = refGen.generate('control', c.name || 'control')
    const control: CycloneDxControl = {
      'bom-ref': bomRef,
      name: c.name,
      status: 'recommended',
    }
    if (c.description) control.description = c.description
    if (c.controlFunction.length) control.category = c.controlFunction[0]

    // Store full control function/nature as properties for lossless round-trip
    const controlProperties: CycloneDxProperty[] = []
    if (c.controlFunction.length) {
      controlProperties.push({ name: 'precogly:control-functions', value: c.controlFunction.join(',') })
    }
    if (c.controlNature) {
      controlProperties.push({ name: 'precogly:control-nature', value: c.controlNature })
    }
    if (controlProperties.length) control.properties = controlProperties

    countermeasureIdToControl.set(c.id, control)
    return control
  })

  // --- Build threats block ---
  // Each GuestThreat maps to one abstract threat + one scenario
  const abstractThreats: CycloneDxThreat[] = []
  const scenarios: CycloneDxScenario[] = []

  for (const threat of threats) {
    const threatBomRef = refGen.generate('threat', threat.name || 'threat')
    threatIdToBomRef.set(threat.id, threatBomRef)

    // Determine affected asset bom-ref
    let affectedRef: string | undefined
    if (threat.targetType === 'dataflow') {
      affectedRef = edgeIdToBomRef.get(threat.targetId)
    } else {
      affectedRef = nodeIdToBomRef.get(threat.targetId)
    }

    // Abstract threat
    const abstractThreat: CycloneDxThreat = {
      'bom-ref': threatBomRef,
      name: threat.name,
      description: threat.description,
    }
    if (threat.category) {
      abstractThreat.categories = [
        { taxonomy: 'stride', id: threat.category, name: getCategoryName(threat.category) },
      ]
    }
    if (affectedRef) abstractThreat.affectedAssets = [affectedRef]

    // Link mitigations from countermeasures that reference this threat
    const mitigationRefs = countermeasures
      .filter((c) => c.threatId === threat.id)
      .map((c) => countermeasureIdToControl.get(c.id)?.['bom-ref'])
      .filter((ref): ref is string => ref != null)
    if (mitigationRefs.length) abstractThreat.mitigations = mitigationRefs

    abstractThreats.push(abstractThreat)

    // Scenario — triage status lives here (per-instance, not per-definition)
    const scenarioBomRef = refGen.generate('scenario', threat.name || 'scenario')
    const scenario: CycloneDxScenario = {
      'bom-ref': scenarioBomRef,
      threat: threatBomRef,
    }
    if (affectedRef) scenario.affectedAssets = [affectedRef]
    scenario.riskScore = {
      level: SEVERITY_TO_CDX_RISK_LEVEL[threat.severity] ?? threat.severity,
    }
    const scenarioProperties: CycloneDxProperty[] = []
    if (threat.status && threat.status !== 'open') {
      scenarioProperties.push({ name: 'precogly:threat-status', value: threat.status })
    }
    if (threat.decisionRationale?.trim()) {
      scenarioProperties.push({ name: 'precogly:decision-rationale', value: threat.decisionRationale.trim() })
    }
    if (scenarioProperties.length > 0) {
      scenario.properties = scenarioProperties
    }
    scenarios.push(scenario)
  }

  // Link control mitigations now that threat bom-refs are populated
  for (const countermeasure of countermeasures) {
    const threatRef = threatIdToBomRef.get(countermeasure.threatId)
    if (threatRef) {
      const matchingControl = countermeasureIdToControl.get(countermeasure.id)
      if (matchingControl) {
        matchingControl.mitigations = [threatRef]
      }
    }
  }

  // --- Assemble document ---
  const document: CycloneDxDocument = {
    specFormat: 'CycloneDX',
    specVersion: '2.0',
    serialNumber: `urn:uuid:${generateUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [
          {
            type: 'application',
            name: 'Precogly Guest Editor',
            version: '1.0.0',
          },
        ],
      },
    },
    blueprints: [blueprint],
  }

  if (controls.length) document.controls = controls
  if (abstractThreats.length || scenarios.length) {
    document.threats = {}
    if (abstractThreats.length) document.threats.threats = abstractThreats
    if (scenarios.length) document.threats.scenarios = scenarios
  }

  return JSON.stringify(document, null, 2)
}

// ---------------------------------------------------------------------------
// Deserialization: CycloneDX 2.0 JSON -> Guest editor state
// ---------------------------------------------------------------------------

export function deserializeCycloneDxToGuest(json: string): DeserializedFile {
  let parsed: Record<string, unknown>
  try {
    parsed = JSON.parse(json)
  } catch {
    throw new Error('Could not parse file as JSON. Check that the file is valid JSON and try again.')
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Could not parse file as JSON. The file content must be a JSON object.')
  }

  if (!parsed.specFormat) {
    throw new Error(
      "This file is not in CycloneDX format. The file must have a 'specFormat' field set to 'CycloneDX'."
    )
  }

  if (parsed.specFormat !== 'CycloneDX') {
    throw new Error(
      `This is not a CycloneDX file. Found specFormat '${String(parsed.specFormat)}' but expected 'CycloneDX'.`
    )
  }

  const specVersion = parsed.specVersion as string
  if (!specVersion?.startsWith('2.')) {
    throw new Error(
      `Unsupported CycloneDX version '${specVersion || 'unknown'}'. Only version 2.x files are supported.`
    )
  }

  const blueprints = parsed.blueprints as CycloneDxBlueprint[] | undefined
  const blueprint = blueprints?.[0]
  const title = blueprint?.name || 'Untitled Diagram'

  // Check for Precogly visualization for lossless round-trip
  const visualizations = blueprint?.visualizations ?? []
  const precoglyViz = visualizations.find(
    (v: CycloneDxVisualization) => v.type === 'precogly-dfd'
  )

  if (precoglyViz?.data) {
    return deserializeFromVisualization(title, precoglyViz, parsed)
  }

  return deserializeFromStructure(title, blueprint, parsed)
}

// ---------------------------------------------------------------------------
// Round-trip deserialization from Precogly visualization data
// ---------------------------------------------------------------------------

function deserializeFromVisualization(
  title: string,
  visualization: CycloneDxVisualization,
  document: Record<string, unknown>
): DeserializedFile {
  // Backend stores canvas_data with snake_case keys (DRF CamelCaseJSONParser
  // converts on input), but the export dumps raw JSON (bypassing the
  // CamelCaseJSONRenderer). Normalize back to camelCase for React Flow
  // and frontend components.
  const data = normalizeSnakeToCamel(visualization.data!) as Record<string, unknown>
  const nodes = (data.nodes ?? []) as unknown as DiagramNode[]
  const edges = (data.edges ?? []) as unknown as DiagramEdge[]
  const notationStyle = data.notationStyle as DFDNotationStyle | undefined
  const systemContext = data.systemContext as GuestSystemContext | undefined

  // Reconstruct threats from the threats block
  const threatsBlock = document.threats as Record<string, unknown> | undefined
  const scenariosArray = (threatsBlock?.scenarios ?? []) as CycloneDxScenario[]
  const abstractThreats = (threatsBlock?.threats ?? []) as CycloneDxThreat[]

  // Build threat bom-ref -> abstract threat map
  const threatRefMap = new Map<string, CycloneDxThreat>()
  for (const abstractThreat of abstractThreats) {
    threatRefMap.set(abstractThreat['bom-ref'], abstractThreat)
  }

  // Build bomRef -> nodeId/edgeId reverse map from visualization data
  // For round-trip we need to match assets back to node IDs
  const bomRefToNodeId = buildBomRefToNodeIdMap(nodes, edges, document)

  // Collect flow bom-refs so we can infer targetType for unresolved refs
  const blueprintForFlows = (document.blueprints as CycloneDxBlueprint[] | undefined)?.[0]
  const flowBomRefs = new Set((blueprintForFlows?.flows ?? []).map((f) => f['bom-ref']))

  const threats: GuestThreat[] = scenariosArray.map(
    (scenario: CycloneDxScenario, index: number) => {
      const abstractThreat = threatRefMap.get(scenario.threat)

      // Determine severity from scenario riskScore
      const riskLevel = scenario.riskScore?.level ?? 'medium'
      const severity = (CDX_RISK_LEVEL_TO_SEVERITY[riskLevel] ?? 'medium') as GuestThreat['severity']

      // Determine STRIDE category from abstract threat
      let category: STRIDECategory | undefined
      const categories = abstractThreat?.categories ?? []
      const strideCategory = categories.find(
        (c) => c.taxonomy === 'stride'
      )
      if (strideCategory?.id) {
        category = strideCategory.id as STRIDECategory
      }

      // Determine target from affectedAssets
      const affectedRef = scenario.affectedAssets?.[0] ?? abstractThreat?.affectedAssets?.[0]
      const { targetId, targetType } = resolveTargetFromBomRef(
        affectedRef,
        bomRefToNodeId,
        nodes,
        flowBomRefs
      )

      // Extract status and rationale from scenario properties (backend export),
      // falling back to abstract threat properties (old guest editor files)
      const { status, decisionRationale } = extractStatusFromProperties(
        scenario.properties ?? abstractThreat?.properties
      )

      return {
        id: scenario['bom-ref'] || `threat-${index}`,
        targetId,
        targetType,
        name: abstractThreat?.name ?? '',
        description: abstractThreat?.description ?? '',
        severity,
        ...(category ? { category } : {}),
        status,
        ...(decisionRationale ? { decisionRationale } : {}),
        createdAt: new Date().toISOString(),
      }
    }
  )

  // Build abstract threat bom-ref -> GuestThreat.id mapping from scenarios
  const threatBomRefToGuestId = new Map<string, string>()
  for (let i = 0; i < scenariosArray.length; i++) {
    threatBomRefToGuestId.set(scenariosArray[i].threat, threats[i].id)
  }

  // Reconstruct countermeasures from controls
  const controlsArray = (document.controls ?? []) as CycloneDxControl[]
  const countermeasures = reconstructCountermeasures(
    controlsArray,
    abstractThreats,
    threatBomRefToGuestId
  )

  return {
    title,
    nodes,
    edges,
    threats,
    countermeasures,
    notationStyle,
    systemContext,
  }
}

// ---------------------------------------------------------------------------
// Third-party CycloneDX import (no visualization data)
// ---------------------------------------------------------------------------

function deserializeFromStructure(
  title: string,
  blueprint: CycloneDxBlueprint | undefined,
  document: Record<string, unknown>
): DeserializedFile {
  const nodes: DiagramNode[] = []
  const edges: DiagramEdge[] = []
  const bomRefToNodeId = new Map<string, string>()
  const bomRefToEdgeId = new Map<string, string>()

  let nextNodeIndex = 0

  // --- Count assets per zone for sizing ---
  const zoneData = blueprint?.zones ?? []
  const assetData = blueprint?.assets ?? []
  const assetsPerZone = new Map<string, number>()
  for (const asset of assetData) {
    if (asset.zone) {
      assetsPerZone.set(asset.zone, (assetsPerZone.get(asset.zone) ?? 0) + 1)
    }
  }

  // --- Generate trust zone nodes ---
  const zoneXStart = 50
  const zoneWidth = 400
  const zoneGap = 50

  for (let i = 0; i < zoneData.length; i++) {
    const zone = zoneData[i]
    const nodeId = `zone-${nextNodeIndex++}`
    bomRefToNodeId.set(zone['bom-ref'], nodeId)
    const childCount = assetsPerZone.get(zone['bom-ref']) ?? 0
    const zoneHeight = Math.max(200, 50 + Math.ceil(childCount / 2) * 120 + 80)
    nodes.push({
      id: nodeId,
      type: 'trustZone',
      position: { x: zoneXStart + i * (zoneWidth + zoneGap), y: 50 },
      data: {
        label: zone.name,
        description: zone.description,
        trustLevel: zone.trustLevel,
      },
      style: { width: zoneWidth, height: zoneHeight },
    } as DiagramNode)
  }

  // --- Generate asset nodes ---
  // Track children per zone for grid positioning
  const zoneChildCount = new Map<string, number>()

  for (const asset of assetData) {
    const nodeId = `node-${nextNodeIndex++}`
    bomRefToNodeId.set(asset['bom-ref'], nodeId)

    const nodeType = ASSET_TYPE_TO_NODE_TYPE[asset.type] ?? 'process'
    let parentId: string | undefined
    let position = { x: 50, y: 400 + nextNodeIndex * 100 }

    if (asset.zone) {
      const zoneNodeId = bomRefToNodeId.get(asset.zone)
      if (zoneNodeId) {
        parentId = zoneNodeId
        const childIndex = zoneChildCount.get(asset.zone) ?? 0
        zoneChildCount.set(asset.zone, childIndex + 1)
        // Grid layout inside zone: 2 columns
        const col = childIndex % 2
        const row = Math.floor(childIndex / 2)
        position = { x: 30 + col * 180, y: 50 + row * 120 }
      }
    }

    nodes.push({
      id: nodeId,
      type: nodeType,
      position,
      parentId,
      data: {
        label: asset.name,
        description: asset.description,
      },
    } as DiagramNode)
  }

  // --- Generate orphan node positioning ---
  // Nodes without a zone that defaulted to y:400+... are fine as-is

  // --- Generate data flow edges ---
  const flowData = blueprint?.flows ?? []
  let edgeIndex = 0

  for (const flow of flowData) {
    const sourceNodeId = bomRefToNodeId.get(flow.source)
    const destNodeId = bomRefToNodeId.get(flow.destination)
    if (!sourceNodeId || !destNodeId) continue

    const edgeId = `edge-${edgeIndex++}`
    bomRefToEdgeId.set(flow['bom-ref'], edgeId)

    edges.push({
      id: edgeId,
      type: 'dataFlow',
      source: sourceNodeId,
      target: destNodeId,
      data: {
        label: flow.name ?? '',
        description: flow.description,
        protocol: flow.protocols?.[0],
        encrypted: flow.encrypted,
        authenticated: flow.authenticated,
      },
    } as DiagramEdge)
  }

  // --- Generate trust boundary edges ---
  const boundaryData = blueprint?.boundaries ?? []
  for (const boundary of boundaryData) {
    const zoneRefA = boundary.zones[0]
    const zoneRefB = boundary.zones[1]
    if (!zoneRefA || !zoneRefB) continue

    const sourceNodeId = bomRefToNodeId.get(zoneRefA)
    const targetNodeId = bomRefToNodeId.get(zoneRefB)
    if (!sourceNodeId || !targetNodeId) continue

    edges.push({
      id: `edge-${edgeIndex++}`,
      type: 'trustBoundary',
      source: sourceNodeId,
      target: targetNodeId,
      data: {
        label: boundary.name ?? '',
      },
    } as DiagramEdge)
  }

  // --- Reconstruct threats ---
  const threatsBlock = document.threats as Record<string, unknown> | undefined
  const abstractThreats = (threatsBlock?.threats ?? []) as CycloneDxThreat[]
  const scenariosArray = (threatsBlock?.scenarios ?? []) as CycloneDxScenario[]

  const threatRefMap = new Map<string, CycloneDxThreat>()
  for (const abstractThreat of abstractThreats) {
    threatRefMap.set(abstractThreat['bom-ref'], abstractThreat)
  }

  // Build combined bomRef -> node/edge map
  const combinedBomRefMap = new Map<string, { id: string; type: 'node' | 'edge' }>()
  for (const [bomRef, nodeId] of bomRefToNodeId) {
    combinedBomRefMap.set(bomRef, { id: nodeId, type: 'node' })
  }
  for (const [bomRef, edgeId] of bomRefToEdgeId) {
    combinedBomRefMap.set(bomRef, { id: edgeId, type: 'edge' })
  }

  // All flow bom-refs from blueprint (for inferring targetType on unresolved refs)
  const allFlowBomRefs = new Set(flowData.map((f) => f['bom-ref']))

  const threats: GuestThreat[] = scenariosArray.map(
    (scenario: CycloneDxScenario, index: number) => {
      const abstractThreat = threatRefMap.get(scenario.threat)
      const riskLevel = scenario.riskScore?.level ?? 'medium'
      const severity = (CDX_RISK_LEVEL_TO_SEVERITY[riskLevel] ?? 'medium') as GuestThreat['severity']

      let category: STRIDECategory | undefined
      const categories = abstractThreat?.categories ?? []
      const strideCategory = categories.find((c) => c.taxonomy === 'stride')
      if (strideCategory?.id) {
        category = strideCategory.id as STRIDECategory
      }

      const affectedRef = scenario.affectedAssets?.[0] ?? abstractThreat?.affectedAssets?.[0]
      let targetId = ''
      let targetType: GuestThreat['targetType'] = 'component'

      if (affectedRef) {
        const mapping = combinedBomRefMap.get(affectedRef)
        if (mapping) {
          targetId = mapping.id
          if (mapping.type === 'edge') {
            targetType = 'dataflow'
          } else {
            const targetNode = nodes.find((n) => n.id === mapping.id)
            targetType = targetNode?.type === 'systemScope' ? 'systemScope' : 'component'
          }
        } else {
          targetType = allFlowBomRefs.has(affectedRef) ? 'dataflow' : 'component'
          console.warn(`[CycloneDX import] Could not resolve bom-ref "${affectedRef}" to a diagram element. The threat will be unattached.`)
        }
      }

      // Extract status and rationale from scenario properties (backend export),
      // falling back to abstract threat properties (old guest editor files)
      const { status, decisionRationale } = extractStatusFromProperties(
        scenario.properties ?? abstractThreat?.properties
      )

      return {
        id: scenario['bom-ref'] || `threat-${index}`,
        targetId,
        targetType,
        name: abstractThreat?.name ?? '',
        description: abstractThreat?.description ?? '',
        severity,
        ...(category ? { category } : {}),
        status,
        ...(decisionRationale ? { decisionRationale } : {}),
        createdAt: new Date().toISOString(),
      }
    }
  )

  // Build abstract threat bom-ref -> GuestThreat.id mapping from scenarios
  const threatBomRefToGuestId = new Map<string, string>()
  for (let i = 0; i < scenariosArray.length; i++) {
    threatBomRefToGuestId.set(scenariosArray[i].threat, threats[i].id)
  }

  // --- Reconstruct countermeasures ---
  const controlsArray = (document.controls ?? []) as CycloneDxControl[]
  const countermeasures = reconstructCountermeasures(
    controlsArray,
    abstractThreats,
    threatBomRefToGuestId
  )

  // --- Reconstruct system context from blueprint fields ---
  const blueprintAssumptions = blueprint?.assumptions ?? []
  const blueprintDataSets = blueprint?.dataSets ?? []

  let systemContext: GuestSystemContext | undefined
  if (blueprintAssumptions.length || blueprintDataSets.length || blueprint?.description) {
    systemContext = {
      session: { facilitator: '', participants: [], meetingDate: '' },
      systemInfo: {
        description: blueprint?.description ?? '',
        criticality: 'medium',
      },
      dataAssets: blueprintDataSets.map((ds, index) => ({
        id: ds['bom-ref'] || `data-asset-${index}`,
        name: ds.name,
        description: ds.description ?? '',
        classification: ds.classification ?? '',
        confidentiality: 'medium' as const,
        integrity: 'medium' as const,
        availability: 'medium' as const,
        complianceTags: [],
        dataSensitivity: [],
      })),
      assumptions: blueprintAssumptions.map((a, index) => ({
        id: a['bom-ref'] || `assumption-${index}`,
        description: a.description,
        validity: (a.validity ?? 'unconfirmed') as GuestAssumption['validity'],
        topics: a.topic ? [a.topic] : [],
      })),
      outOfScopeItems: [],
    }
  }

  return {
    title,
    nodes,
    edges,
    threats,
    countermeasures,
    systemContext,
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizeSnakeToCamel(obj: unknown): unknown {
  if (Array.isArray(obj)) {
    return obj.map(normalizeSnakeToCamel)
  }
  if (obj !== null && typeof obj === 'object') {
    const result: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const camelKey = key.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase())
      result[camelKey] = normalizeSnakeToCamel(value)
    }
    return result
  }
  return obj
}

function reconstructCountermeasures(
  controlsArray: CycloneDxControl[],
  abstractThreats: CycloneDxThreat[],
  threatBomRefToGuestId: Map<string, string>
): GuestCountermeasure[] {

  // Build control bom-ref -> threat bom-ref mapping from abstract threat mitigations
  const controlRefToThreatRefs = new Map<string, string[]>()
  for (const abstractThreat of abstractThreats) {
    for (const mitigationRef of abstractThreat.mitigations ?? []) {
      const existing = controlRefToThreatRefs.get(mitigationRef) ?? []
      existing.push(abstractThreat['bom-ref'])
      controlRefToThreatRefs.set(mitigationRef, existing)
    }
  }

  // Also check control.mitigations which reference threat bom-refs
  const controlRefToThreatRefsFromControl = new Map<string, string[]>()
  for (const control of controlsArray) {
    if (control.mitigations?.length) {
      controlRefToThreatRefsFromControl.set(control['bom-ref'], control.mitigations)
    }
  }

  return controlsArray.map((control, index) => {
    // Find linked threat
    let threatId = ''

    // Check mitigations on the control itself (threat bom-refs)
    const threatRefsFromControl = controlRefToThreatRefsFromControl.get(control['bom-ref']) ?? []
    for (const threatRef of threatRefsFromControl) {
      const abstractThreat = abstractThreats.find((t) => t['bom-ref'] === threatRef)
      if (abstractThreat) {
        const matchedThreatId = threatBomRefToGuestId.get(abstractThreat['bom-ref'])
        if (matchedThreatId) {
          threatId = matchedThreatId
          break
        }
      }
    }

    // Fallback: check abstract threat mitigations pointing to this control
    if (!threatId) {
      const threatRefs = controlRefToThreatRefs.get(control['bom-ref']) ?? []
      for (const threatRef of threatRefs) {
        const abstractThreat = abstractThreats.find((t) => t['bom-ref'] === threatRef)
        if (abstractThreat) {
          const matchedThreatId = threatBomRefToGuestId.get(abstractThreat['bom-ref'])
          if (matchedThreatId) {
            threatId = matchedThreatId
            break
          }
        }
      }
    }

    // Extract control function/nature from properties (new format) or fall back to category (old format)
    const { controlFunction, controlNature } = extractControlFields(control)

    return {
      id: control['bom-ref'] || `countermeasure-${index}`,
      threatId,
      name: control.name,
      description: control.description ?? '',
      controlFunction,
      controlNature,
      createdAt: new Date().toISOString(),
    }
  })
}

/**
 * Build a bom-ref -> node/edge ID reverse map for round-trip deserialization.
 *
 * Uses name-based matching with consumed-set disambiguation: when multiple
 * blueprint entries share the same name+type (or same source+destination for
 * flows), each match is consumed so the next entry picks the next candidate.
 */
function buildBomRefToNodeIdMap(
  nodes: DiagramNode[],
  edges: DiagramEdge[],
  document: Record<string, unknown>
): Map<string, { id: string; type: 'node' | 'edge' }> {
  const map = new Map<string, { id: string; type: 'node' | 'edge' }>()

  const blueprints = document.blueprints as CycloneDxBlueprint[] | undefined
  const blueprint = blueprints?.[0]
  if (!blueprint) return map

  const claimedNodeIds = new Set<string>()
  const claimedEdgeIds = new Set<string>()

  // Map zone bom-refs to zone nodes by name (consume each match)
  const zoneNodes = nodes.filter((n) => n.type === 'trustZone')
  for (const zone of blueprint.zones ?? []) {
    const match = zoneNodes.find((n) => n.data.label === zone.name && !claimedNodeIds.has(n.id))
    if (match) {
      claimedNodeIds.add(match.id)
      map.set(zone['bom-ref'], { id: match.id, type: 'node' })
    }
  }

  // Map asset bom-refs to asset nodes by name + type (consume each match)
  const assetNodeTypes = ['process', 'datastore', 'humanActor', 'systemActor']
  const assetNodes = nodes.filter((n) => assetNodeTypes.includes(n.type ?? ''))
  for (const asset of blueprint.assets ?? []) {
    const expectedNodeType = ASSET_TYPE_TO_NODE_TYPE[asset.type]
    const match = assetNodes.find((n) =>
      n.data.label === asset.name
      && (!expectedNodeType || n.type === expectedNodeType)
      && !claimedNodeIds.has(n.id)
    )
    if (match) {
      claimedNodeIds.add(match.id)
      map.set(asset['bom-ref'], { id: match.id, type: 'node' })
    }
  }

  // Map flow bom-refs to dataFlow edges by resolved source + destination,
  // then by label, consuming each match to handle multiple same-pair flows
  const dataFlowEdges = edges.filter((e) => e.type === 'dataFlow')
  for (const flow of blueprint.flows ?? []) {
    const sourceMapping = map.get(flow.source)
    const destMapping = map.get(flow.destination)
    if (!sourceMapping || !destMapping) continue

    const candidates = dataFlowEdges.filter(
      (e) => e.source === sourceMapping.id && e.target === destMapping.id && !claimedEdgeIds.has(e.id)
    )
    const match = candidates.find(
      (e) => flow.name && (e.data as Record<string, unknown>)?.label === flow.name
    ) ?? candidates[0]
    if (match) {
      claimedEdgeIds.add(match.id)
      map.set(flow['bom-ref'], { id: match.id, type: 'edge' })
    }
  }

  return map
}

function resolveTargetFromBomRef(
  bomRef: string | undefined,
  bomRefMap: Map<string, { id: string; type: 'node' | 'edge' }>,
  nodes: DiagramNode[],
  flowBomRefs: Set<string>
): { targetId: string; targetType: GuestThreat['targetType'] } {
  if (!bomRef) return { targetId: '', targetType: 'component' }

  const mapping = bomRefMap.get(bomRef)
  if (!mapping) {
    const inferredType: GuestThreat['targetType'] = flowBomRefs.has(bomRef) ? 'dataflow' : 'component'
    console.warn(`[CycloneDX import] Could not resolve bom-ref "${bomRef}" to a diagram element. The threat will be unattached.`)
    return { targetId: '', targetType: inferredType }
  }

  if (mapping.type === 'edge') {
    return { targetId: mapping.id, targetType: 'dataflow' }
  }

  const node = nodes.find((n) => n.id === mapping.id)
  const targetType: GuestThreat['targetType'] =
    node?.type === 'systemScope' ? 'systemScope' : 'component'
  return { targetId: mapping.id, targetType }
}

function extractStatusFromProperties(
  properties?: CycloneDxProperty[]
): { status: ThreatStatus; decisionRationale?: string } {
  const statusProp = properties?.find((p) => p.name === 'precogly:threat-status')
  const rationaleProp = properties?.find((p) => p.name === 'precogly:decision-rationale')
  const validStatuses: ThreatStatus[] = ['open', 'accept', 'mitigate', 'delegate', 'eliminate']
  const status: ThreatStatus = validStatuses.includes(statusProp?.value as ThreatStatus)
    ? (statusProp!.value as ThreatStatus)
    : 'open'
  return {
    status,
    ...(rationaleProp?.value ? { decisionRationale: rationaleProp.value } : {}),
  }
}

function getCategoryName(strideId: string): string {
  const names: Record<string, string> = {
    spoofing: 'Spoofing',
    tampering: 'Tampering',
    repudiation: 'Repudiation',
    'information-disclosure': 'Information Disclosure',
    'denial-of-service': 'Denial of Service',
    'elevation-of-privilege': 'Elevation of Privilege',
  }
  return names[strideId] ?? strideId
}

const VALID_CONTROL_FUNCTIONS: ControlFunction[] = ['preventive', 'detective', 'corrective', 'deterrent', 'recovery', 'compensating']
const VALID_CONTROL_NATURES: ControlNature[] = ['technical', 'administrative', 'physical']

/**
 * Extract controlFunction and controlNature from a CycloneDX control.
 * Handles both new format (with precogly:control-functions/nature properties)
 * and old format (single category field that mixed function and nature).
 */
function extractControlFields(control: CycloneDxControl): {
  controlFunction: ControlFunction[]
  controlNature: ControlNature
} {
  const properties = control.properties ?? []
  const functionsProp = properties.find((p) => p.name === 'precogly:control-functions')
  const natureProp = properties.find((p) => p.name === 'precogly:control-nature')

  if (functionsProp) {
    // New format: read from properties
    const parsedFunctions = functionsProp.value
      .split(',')
      .filter((f): f is ControlFunction => VALID_CONTROL_FUNCTIONS.includes(f as ControlFunction))
    const parsedNature = VALID_CONTROL_NATURES.includes(natureProp?.value as ControlNature)
      ? (natureProp!.value as ControlNature)
      : 'technical'
    return {
      controlFunction: parsedFunctions.length > 0 ? parsedFunctions : ['preventive'],
      controlNature: parsedNature,
    }
  }

  // Old format migration: category was a single value mixing function and nature
  const oldCategory = control.category ?? 'preventive'
  if (oldCategory === 'procedural') {
    return { controlFunction: ['preventive'], controlNature: 'administrative' }
  }
  const migratedFunction = VALID_CONTROL_FUNCTIONS.includes(oldCategory as ControlFunction)
    ? (oldCategory as ControlFunction)
    : 'preventive'
  return { controlFunction: [migratedFunction], controlNature: 'technical' }
}

function generateUUID(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID()
  }
  // Fallback for older browsers
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0
    const v = c === 'x' ? r : (r & 0x3) | 0x8
    return v.toString(16)
  })
}
