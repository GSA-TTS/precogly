/**
 * AI settings page — two tabs for one organization's AI configuration:
 *   - Providers: manage "bring your own model" endpoints (one default is used by
 *     AI features; the rest are ready-to-switch alternatives). The API key is
 *     write-only — the form never shows the stored key, only offers to replace
 *     it, and "Test connection" probes the endpoint server-side so the secret
 *     never comes back to the browser.
 *   - Usage: token/cost usage across the org's AI features (the "you spent $X on
 *     AI" report).
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { useWorkspace } from '@/contexts/WorkspaceContext'
import {
  useAIProviders,
  useCreateAIProvider,
  useUpdateAIProvider,
  useDeleteAIProvider,
  useTestAIProviderConnection,
} from '@/features/ai/api/aiProviders'
import type { AIProviderConfig } from '@/features/ai/types/aiProvider'
import { AIUsageReport } from '@/features/ai/components/AIUsageReport'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Plus, Pencil, Trash2, Loader2, Plug, Star } from 'lucide-react'

// Shape of the create/edit form. `apiKey` is always blank on open: for an edit we
// never load the stored key, and leaving it blank means "keep it".
interface ProviderForm {
  name: string
  baseUrl: string
  model: string
  requestTimeout: string
  apiKey: string
  isDefault: boolean
  enabled: boolean
}

const EMPTY_FORM: ProviderForm = {
  name: '',
  baseUrl: 'http://localhost:1234/v1',
  model: '',
  requestTimeout: '60',
  apiKey: '',
  isDefault: false,
  enabled: true,
}

export function AIProviderSettings() {
  const { currentOrganization, isLoading: workspaceLoading } = useWorkspace()
  const { data: providers = [], isLoading: providersLoading } = useAIProviders(
    currentOrganization?.id
  )
  const createMutation = useCreateAIProvider()
  const updateMutation = useUpdateAIProvider()
  const deleteMutation = useDeleteAIProvider()
  const testMutation = useTestAIProviderConnection()

  // `editing` is the config being edited, or null for the create flow. The dialog
  // is open whenever `form` is non-null.
  const [form, setForm] = useState<ProviderForm | null>(null)
  const [editing, setEditing] = useState<AIProviderConfig | null>(null)
  // Which row's connection is currently being probed (for a per-row spinner).
  const [testingId, setTestingId] = useState<number | null>(null)

  if (workspaceLoading || providersLoading) {
    return <div>Loading...</div>
  }

  if (!currentOrganization) {
    return <div>No organization selected.</div>
  }

  const openCreate = () => {
    setEditing(null)
    setForm({ ...EMPTY_FORM })
  }

  const openEdit = (config: AIProviderConfig) => {
    setEditing(config)
    setForm({
      name: config.name,
      baseUrl: config.baseUrl,
      model: config.model,
      requestTimeout: String(config.requestTimeout),
      apiKey: '',
      isDefault: config.isDefault,
      enabled: config.enabled,
    })
  }

  const closeDialog = () => {
    setForm(null)
    setEditing(null)
  }

  const isSaving = createMutation.isPending || updateMutation.isPending

  const handleSubmit = () => {
    if (!form || !form.name.trim()) return
    const timeout = parseInt(form.requestTimeout, 10)

    if (editing) {
      updateMutation.mutate(
        {
          id: editing.id,
          data: {
            name: form.name,
            baseUrl: form.baseUrl,
            model: form.model,
            requestTimeout: Number.isFinite(timeout) ? timeout : undefined,
            // Empty string is dropped server-side as "keep existing key".
            apiKey: form.apiKey,
            isDefault: form.isDefault,
            enabled: form.enabled,
          },
        },
        {
          onSuccess: () => {
            toast.success('Provider updated')
            closeDialog()
          },
          onError: () => toast.error('Could not update provider'),
        }
      )
    } else {
      createMutation.mutate(
        {
          organization: currentOrganization.id,
          name: form.name,
          baseUrl: form.baseUrl,
          model: form.model,
          requestTimeout: Number.isFinite(timeout) ? timeout : undefined,
          apiKey: form.apiKey || undefined,
          isDefault: form.isDefault,
          enabled: form.enabled,
        },
        {
          onSuccess: () => {
            toast.success('Provider added')
            closeDialog()
          },
          onError: () => toast.error('Could not add provider'),
        }
      )
    }
  }

  const handleDelete = (config: AIProviderConfig) => {
    if (!confirm(`Delete the provider "${config.name}"?`)) return
    deleteMutation.mutate(config.id, {
      onSuccess: () => toast.success('Provider deleted'),
      onError: () => toast.error('Could not delete provider'),
    })
  }

  const handleTest = (config: AIProviderConfig) => {
    setTestingId(config.id)
    testMutation.mutate(config.id, {
      onSuccess: (health) => {
        if (health.ok) {
          toast.success(`${config.name}: ${health.detail}`)
        } else {
          toast.error(`${config.name}: ${health.detail}`)
        }
      },
      onError: () => toast.error(`${config.name}: connection test failed`),
      onSettled: () => setTestingId(null),
    })
  }

  return (
    <Tabs defaultValue="providers" className="space-y-6">
      <TabsList>
        <TabsTrigger value="providers">Providers</TabsTrigger>
        <TabsTrigger value="usage">Usage</TabsTrigger>
      </TabsList>

      <TabsContent value="providers" className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>AI Providers</CardTitle>
              <CardDescription>
                Connect {currentOrganization.name} to your own AI model endpoint. The
                provider marked <span className="font-medium">Default</span> is used by
                AI features; if none is set, the deployment-wide default applies.
              </CardDescription>
            </div>
            <Button onClick={openCreate}>
              <Plus className="mr-2 h-4 w-4" />
              Add Provider
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {providers.length === 0 ? (
            <p className="text-muted-foreground">
              No AI providers configured. Add one to point this organization at your
              own model.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Model</TableHead>
                  <TableHead>Base URL</TableHead>
                  <TableHead>API Key</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-32">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {providers.map((provider) => (
                  <TableRow key={provider.id}>
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        {provider.name}
                        {provider.isDefault && (
                          <Badge className="bg-blue-100 text-blue-800 gap-1">
                            <Star className="h-3 w-3" />
                            Default
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{provider.model}</TableCell>
                    <TableCell className="text-muted-foreground max-w-[220px] truncate">
                      {provider.baseUrl}
                    </TableCell>
                    <TableCell>
                      {provider.hasApiKey ? (
                        <Badge className="bg-green-100 text-green-800">Set</Badge>
                      ) : (
                        <Badge className="bg-gray-100 text-gray-800">None</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {provider.enabled ? (
                        <Badge className="bg-green-100 text-green-800">Enabled</Badge>
                      ) : (
                        <Badge className="bg-gray-100 text-gray-800">Disabled</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8"
                          title="Test connection"
                          onClick={() => handleTest(provider)}
                          disabled={testingId === provider.id}
                        >
                          {testingId === provider.id ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <Plug className="h-4 w-4" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8"
                          title="Edit"
                          onClick={() => openEdit(provider)}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-destructive hover:text-destructive"
                          title="Delete"
                          onClick={() => handleDelete(provider)}
                          disabled={deleteMutation.isPending}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={!!form} onOpenChange={(open) => !open && closeDialog()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit Provider' : 'Add Provider'}</DialogTitle>
            <DialogDescription>
              Point an OpenAI-compatible endpoint (LM Studio, Ollama, a hosted API)
              at this organization.
            </DialogDescription>
          </DialogHeader>
          {form && (
            <div className="space-y-4">
              {!editing && (
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span>Presets:</span>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="h-7 px-2 text-xs"
                    onClick={() =>
                      setForm({
                        ...form,
                        name: form.name || 'GSA USAi',
                        baseUrl: 'https://api.usai.gsa.gov/v1',
                        model: form.model || 'claude-opus-4-7',
                        isDefault: true,
                      })
                    }
                  >
                    GSA USAi
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="h-7 px-2 text-xs"
                    onClick={() =>
                      setForm({
                        ...form,
                        name: form.name || 'Local LM Studio',
                        baseUrl: 'http://localhost:1234/v1',
                        model: form.model || 'local-model',
                      })
                    }
                  >
                    LM Studio
                  </Button>
                </div>
              )}
              <div className="space-y-2">
                <Label htmlFor="provider-name">Name</Label>
                <Input
                  id="provider-name"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="e.g., Local LM Studio"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="provider-base-url">Base URL</Label>
                <Input
                  id="provider-base-url"
                  value={form.baseUrl}
                  onChange={(e) => setForm({ ...form, baseUrl: e.target.value })}
                  placeholder="http://localhost:1234/v1"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="provider-model">Model</Label>
                <Input
                  id="provider-model"
                  value={form.model}
                  onChange={(e) => setForm({ ...form, model: e.target.value })}
                  placeholder="e.g., gpt-oss-20b"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="provider-key">API Key</Label>
                <Input
                  id="provider-key"
                  type="password"
                  value={form.apiKey}
                  onChange={(e) => setForm({ ...form, apiKey: e.target.value })}
                  placeholder={
                    editing?.hasApiKey
                      ? 'Leave blank to keep the existing key'
                      : 'Optional — local servers usually need none'
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="provider-timeout">Request timeout (seconds)</Label>
                <Input
                  id="provider-timeout"
                  type="number"
                  min={1}
                  value={form.requestTimeout}
                  onChange={(e) => setForm({ ...form, requestTimeout: e.target.value })}
                  className="max-w-[140px]"
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <Label htmlFor="provider-default">Default provider</Label>
                  <p className="text-sm text-muted-foreground">
                    Use this endpoint for AI features in this organization.
                  </p>
                </div>
                <Switch
                  id="provider-default"
                  checked={form.isDefault}
                  onCheckedChange={(checked) => setForm({ ...form, isDefault: checked })}
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <Label htmlFor="provider-enabled">Enabled</Label>
                  <p className="text-sm text-muted-foreground">
                    Disabled providers are kept but never used.
                  </p>
                </div>
                <Switch
                  id="provider-enabled"
                  checked={form.enabled}
                  onCheckedChange={(checked) => setForm({ ...form, enabled: checked })}
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={closeDialog}>
              Cancel
            </Button>
            <Button onClick={handleSubmit} disabled={!form?.name.trim() || isSaving}>
              {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {editing ? 'Save' : 'Add'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      </TabsContent>

      <TabsContent value="usage">
        <AIUsageReport organizationId={currentOrganization.id} />
      </TabsContent>
    </Tabs>
  )
}
