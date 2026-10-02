import {
  Package,
  Loader2,
  Eye,
  Check,
  Download,
  ShieldCheck,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import type { UnifiedPack } from './unified-pack'
import { packTypeColors } from '../constants'

export function CatalogPackCard({
  pack,
  onImport,
  onPreview,
  onValidate,
  isImporting,
  isValidating,
  isSecurityTeam,
}: {
  pack: UnifiedPack
  onImport: (pack: UnifiedPack) => void
  onPreview: (pack: UnifiedPack) => void
  onValidate?: (pack: UnifiedPack) => void
  isImporting: boolean
  isValidating?: boolean
  isSecurityTeam: boolean
}) {
  return (
    <div className="border rounded-lg p-4 space-y-3 hover:border-primary/50 transition-colors">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-muted rounded-lg">
            <Package className="h-5 w-5 text-muted-foreground" />
          </div>
          <div>
            <h3 className="font-semibold">{pack.name}</h3>
            <Badge
              variant="secondary"
              className={`text-xs ${packTypeColors[pack.packType] || 'bg-gray-100'}`}
            >
              {pack.packType}
            </Badge>
          </div>
        </div>
      </div>

      <p className="text-sm text-muted-foreground line-clamp-3">
        {pack.description || 'No description available'}
      </p>

      {pack.dependsOn.length > 0 && (
        <p className="text-xs text-muted-foreground">
          Depends on: {pack.dependsOn.map((d) => d.name).join(', ')}
        </p>
      )}

      <div className="flex items-center justify-between pt-2 border-t">
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="ghost"
            onClick={() => onPreview(pack)}
            title="Preview pack contents"
          >
            <Eye className="h-4 w-4 mr-1" />
            Preview
          </Button>
          {isSecurityTeam && onValidate && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => onValidate(pack)}
              disabled={isValidating}
              title="Validate pack references"
            >
              {isValidating ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <ShieldCheck className="h-4 w-4 mr-1" />
              )}
              Validate
            </Button>
          )}
        </div>
        <div className="flex items-center gap-2">
          {pack.isImported ? (
            <Badge variant="outline" className="text-green-600 border-green-600">
              <Check className="mr-1 h-3 w-3" />
              Imported
            </Badge>
          ) : isSecurityTeam ? (
            <Button size="sm" onClick={() => onImport(pack)} disabled={isImporting}>
              {isImporting ? (
                <Loader2 className="mr-2 h-3 w-3 animate-spin" />
              ) : (
                <Download className="mr-2 h-3 w-3" />
              )}
              Import
            </Button>
          ) : null}
        </div>
      </div>
    </div>
  )
}
