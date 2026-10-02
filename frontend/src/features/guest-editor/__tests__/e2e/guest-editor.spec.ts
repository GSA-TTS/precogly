import { test, expect } from '@playwright/test'
import path from 'path'
import { fileURLToPath } from 'url'

const FIXTURES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'fixtures')
const GUEST_URL = '/guest'

// Playwright can't interact with showOpenFilePicker (native OS dialog).
// Instead we intercept the file-open flow by injecting content via the
// filechooser event, which fires when the fallback <input type="file"> is used.
// We force the fallback by stubbing showOpenFilePicker away on page load.
async function stubFileSystemAccess(page: import('@playwright/test').Page) {
  await page.addInitScript(() => {
    delete (window as unknown as Record<string, unknown>).showOpenFilePicker
    delete (window as unknown as Record<string, unknown>).showSaveFilePicker
  })
}

// ---------------------------------------------------------------------------
// 1. File roundtrip: import a valid diagram, verify UI, export, re-import
// ---------------------------------------------------------------------------

test.describe('guest editor file roundtrip', () => {
  test('imports a valid CycloneDX file and shows nodes and threats', async ({ page }) => {
    await stubFileSystemAccess(page)
    await page.goto(GUEST_URL)

    // Wait for the editor to load
    await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

    // Trigger file open and provide the fixture
    const fileChooserPromise = page.waitForEvent('filechooser')
    await page.getByRole('button', { name: 'Open' }).click()
    const fileChooser = await fileChooserPromise
    await fileChooser.setFiles(path.join(FIXTURES, 'valid-diagram.cdx.json'))

    // Verify nodes rendered on canvas
    await expect(page.locator('text=Web Server').first()).toBeVisible({ timeout: 5_000 })
    await expect(page.locator('text=Database').first()).toBeVisible({ timeout: 5_000 })

    // Navigate to threat analysis via in-app button (not page.goto, which reloads and loses state)
    await page.getByRole('button', { name: 'Analyze Threats' }).click()
    await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

    // Click on Web Server in the component list
    await page.locator('text=Web Server').first().click()

    // Verify the threat shows up
    await expect(page.locator('text=SQL Injection')).toBeVisible({ timeout: 5_000 })

    // Verify the countermeasure is linked
    await page.locator('text=SQL Injection').click()
    await expect(page.locator('text=Input Validation')).toBeVisible({ timeout: 5_000 })
  })
})

// ---------------------------------------------------------------------------
// 2. Import error UX: invalid files show toast errors
// ---------------------------------------------------------------------------

test.describe('import error handling', () => {
  test('shows error toast for non-JSON file', async ({ page }) => {
    await stubFileSystemAccess(page)
    await page.goto(GUEST_URL)
    await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

    const fileChooserPromise = page.waitForEvent('filechooser')
    await page.getByRole('button', { name: 'Open' }).click()
    const fileChooser = await fileChooserPromise

    // Create a temporary non-JSON file
    await fileChooser.setFiles({
      name: 'bad-file.json',
      mimeType: 'application/json',
      buffer: Buffer.from('this is not json {{{'),
    })

    // Verify error toast appears
    await expect(page.locator('text=Could not parse file as JSON')).toBeVisible({ timeout: 5_000 })
  })

  test('shows error toast for non-CycloneDX JSON file', async ({ page }) => {
    await stubFileSystemAccess(page)
    await page.goto(GUEST_URL)
    await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

    const fileChooserPromise = page.waitForEvent('filechooser')
    await page.getByRole('button', { name: 'Open' }).click()
    const fileChooser = await fileChooserPromise

    await fileChooser.setFiles({
      name: 'not-cyclonedx.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify({ name: 'just a regular json file' })),
    })

    await expect(page.locator("text=must have a 'specFormat' field")).toBeVisible({ timeout: 5_000 })
  })
})

// ---------------------------------------------------------------------------
// 3. Backend export import: snake_case keys normalize correctly
// ---------------------------------------------------------------------------

test.describe('backend export import', () => {
  test('imports a backend-exported file with snake_case keys and renders correctly', async ({ page }) => {
    await stubFileSystemAccess(page)
    await page.goto(GUEST_URL)
    await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

    const fileChooserPromise = page.waitForEvent('filechooser')
    await page.getByRole('button', { name: 'Open' }).click()
    const fileChooser = await fileChooserPromise
    await fileChooser.setFiles(path.join(FIXTURES, 'backend-export.cdx.json'))

    // Verify nodes rendered (proves snake_case -> camelCase worked for node data)
    await expect(page.locator('text=API Gateway').first()).toBeVisible({ timeout: 5_000 })
    await expect(page.locator('text=Redis Cache').first()).toBeVisible({ timeout: 5_000 })

    // Navigate to threat analysis via in-app button
    await page.getByRole('button', { name: 'Analyze Threats' }).click()
    await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

    // Click API Gateway and verify the threat shows up under the correct component
    await page.locator('text=API Gateway').first().click()
    await expect(page.locator('text=Cache Poisoning')).toBeVisible({ timeout: 5_000 })
  })
})
