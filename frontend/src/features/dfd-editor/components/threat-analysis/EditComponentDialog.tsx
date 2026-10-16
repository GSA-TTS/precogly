import { useState, useEffect } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { COMPONENT_KINDS, type ComponentKind } from '@/types/domain'
import { useUpdateComponent, useZones, type OrgsystemComponent } from '@/features/threat-models/api/components'
import { toast } from 'sonner'

interface EditComponentDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  component: OrgsystemComponent | null
  blueprintId?: number
}

export function EditComponentDialog({
  open,
  onOpenChange,
  component,
  blueprintId,
}: EditComponentDialogProps) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [kind, setKind] = useState<string>('default')
  const [zone, setZone] = useState<string>('none')

  const { data: trustZones } = useZones({ blueprint: blueprintId ?? component?.blueprint })
  const updateComponent = useUpdateComponent()

  useEffect(() => {
    if (component) {
      setName(component.name || '')
      setDescription(component.description || '')
      setKind(component.kind || 'default')
      setZone(component.zone ? String(component.zone) : 'none')
    }
  }, [component])

  const handleSave = () => {
    if (!component || !name.trim()) return

    updateComponent.mutate(
      {
        componentId: component.id,
        data: {
          name: name.trim(),
          description: description.trim(),
          kind: kind === 'default' ? '' : (kind as ComponentKind),
          zone: zone && zone !== 'none' ? parseInt(zone, 10) : null,
        },
      },
      {
        onSuccess: () => {
          toast.success('Component updated')
          onOpenChange(false)
        },
        onError: () => {
          toast.error('Failed to update component')
        },
      }
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Edit Component</DialogTitle>
          <DialogDescription>
            Update component name, kind, zone, and description.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label htmlFor="edit-component-name">Component Name *</Label>
            <Input
              id="edit-component-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Component name..."
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="edit-component-kind">Kind</Label>
            <Select value={kind} onValueChange={setKind}>
              <SelectTrigger id="edit-component-kind">
                <SelectValue placeholder="Default from category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="default">Default from category</SelectItem>
                {COMPONENT_KINDS.map((k) => (
                  <SelectItem key={k.value} value={k.value}>
                    {k.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="edit-component-zone">Trust Zone</Label>
            <Select value={zone} onValueChange={setZone}>
              <SelectTrigger id="edit-component-zone">
                <SelectValue placeholder="None (no trust zone)" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">None</SelectItem>
                {trustZones?.map((z) => (
                  <SelectItem key={z.id} value={String(z.id)}>
                    {z.name}{z.trustLevel !== null ? ` (Trust Level: ${z.trustLevel})` : ''}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="edit-component-desc">Description</Label>
            <Textarea
              id="edit-component-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Component description..."
              rows={3}
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={!name.trim() || updateComponent.isPending}>
            Save Changes
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
