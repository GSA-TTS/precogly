/**
 * Type definitions for library items.
 */

import type { TaxonomyEntry } from '@/types/domain'

export interface ComponentLibrary {
  id: number
  name: string
  category: string
  componentType: string
  provider: string
  organization?: number
  sourcePack?: number
  sourcePackName?: string
  sourcePackSlug?: string
  createdAt: string
  updatedAt: string
}

export interface ThreatLibrary {
  id: number
  name: string
  description?: string
  taxonomyEntries?: TaxonomyEntry[]
  organization?: number
  sourcePack?: number
  sourcePackName?: string
  sourcePackSlug?: string
  createdAt: string
  updatedAt: string
}

export interface CountermeasureLibrary {
  id: number
  name: string
  description?: string
  controlFunctions: string[]
  controlNature: string
  cost: 'low' | 'medium' | 'high'
  defaultStatus?: 'gap' | 'platform'
  organization?: number
  sourcePack?: number
  sourcePackName?: string
  sourcePackSlug?: string
  createdAt: string
  updatedAt: string
}

export interface DFDTemplate {
  id: number
  name: string
  description?: string
  category: string
  diagramType: string
  canvasData?: Record<string, unknown>
  organization?: number
  sourcePack?: number
  sourcePackName?: string
  sourcePackSlug?: string
  createdAt: string
  updatedAt: string
}

export interface StandardRequirement {
  id: number
  framework: number
  frameworkName: string
  sourcePack?: number
  sectionCode: string
  description: string
  parent?: number
  createdAt: string
  updatedAt: string
}

export interface ExternalTaxonomy {
  id: number
  slug: string
  name: string
  description: string
  sourceUrl: string
  version: string
  sourcePack?: number
  entryCount: number
}
