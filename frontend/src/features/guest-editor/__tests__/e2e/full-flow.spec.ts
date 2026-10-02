import { test, expect, type Page } from '@playwright/test'

const GUEST_URL = '/guest'

async function stubFileSystemAccess(page: Page) {
  await page.addInitScript(() => {
    delete (window as unknown as Record<string, unknown>).showOpenFilePicker
    delete (window as unknown as Record<string, unknown>).showSaveFilePicker
  })
}

const DEFAULT_LABELS: Record<string, string> = {
  'Human Actor': 'New Human Actor',
  'System Actor': 'New System Actor',
  'Process': 'New Process',
  'Data Store': 'New Data Store',
}

async function placeAndRenameNode(page: Page, sidebarLabel: string, newName: string) {
  await page.locator(`text=${sidebarLabel}`).first().click()
  const defaultLabel = DEFAULT_LABELS[sidebarLabel] ?? sidebarLabel
  const node = page.locator(`.react-flow__node:has-text("${defaultLabel}")`)
  await node.waitFor({ timeout: 3000 })
  await node.dblclick()
  const textarea = page.locator('.react-flow__node textarea')
  await textarea.waitFor({ timeout: 3000 })
  await textarea.fill(newName)
  await textarea.press('Control+Enter')
  await textarea.waitFor({ state: 'detached', timeout: 2000 })
}

async function dragNode(page: Page, nodeText: string, deltaX: number, deltaY: number) {
  const node = page.locator(`.react-flow__node:has-text("${nodeText}")`)
  const box = await node.boundingBox()
  if (!box) throw new Error(`Node "${nodeText}" not found on canvas`)
  const centerX = box.x + box.width / 2
  const centerY = box.y + box.height / 2
  await page.mouse.move(centerX, centerY)
  await page.mouse.down()
  await page.mouse.move(centerX + deltaX, centerY + deltaY, { steps: 5 })
  await page.mouse.up()
}

test.describe('full threat modeling workflow', () => {
  test('build diagram, add threats and countermeasures, save and reimport', async ({ page }) => {
    test.setTimeout(60_000)
    await stubFileSystemAccess(page)
    await page.goto(GUEST_URL)
    await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

    // ---- System context ----
    await page.getByRole('button', { name: 'Add / Edit Context' }).click()
    await page.locator('#facilitator').fill('Security Team')
    await page.getByRole('button', { name: 'System' }).click()
    await page.locator('#system-description').fill('Mobile banking application')
    await page.keyboard.press('Escape')
    await expect(page.locator('text=System Context')).not.toBeVisible({ timeout: 2000 })

    // ---- Build DFD: place nodes, drag apart so they don't stack ----
    await placeAndRenameNode(page, 'Human Actor', 'Mobile User')
    await dragNode(page, 'Mobile User', -300, 0)

    await placeAndRenameNode(page, 'Process', 'API Server')
    await dragNode(page, 'API Server', 0, 200)

    await placeAndRenameNode(page, 'Data Store', 'Account DB')
    await dragNode(page, 'Account DB', 300, 0)

    // ---- Threat analysis ----
    await page.getByRole('button', { name: 'Analyze Threats' }).click()
    await page.waitForURL('**/guest/threats')

    await page.locator('text=API Server').first().click()

    // Add a threat
    await page.getByRole('button', { name: 'Add', exact: true }).click()
    await page.locator('#threat-name').fill('SQL Injection')
    await page.locator('#threat-description').fill('Attacker injects malicious SQL')
    await page.locator('#threat-severity').click()
    await page.getByRole('option', { name: 'High' }).click()
    await page.locator('#threat-category').click()
    await page.getByRole('option', { name: 'Tampering' }).click()
    await page.getByRole('button', { name: 'Add Threat' }).click()

    await expect(page.locator('text=SQL Injection')).toBeVisible()

    // Select the threat to reveal countermeasures column
    await page.locator('text=SQL Injection').click()

    // Add countermeasure
    await page.getByRole('button', { name: 'Add', exact: true }).last().click()
    await page.locator('#countermeasure-name').fill('Input Validation')
    await page.locator('#countermeasure-description').fill('Validate all user inputs')
    await page.locator('[role="dialog"]').getByRole('button', { name: 'Add' }).click()

    await expect(page.locator('text=Input Validation')).toBeVisible()

    // Edit threat: triage as Mitigate
    const threatRow = page.locator('div[role="button"]:has-text("SQL Injection")')
    await threatRow.hover()
    await threatRow.locator('button').first().click()
    await page.locator('#threat-status').click()
    await page.getByRole('option', { name: 'Mitigate' }).click()
    await page.locator('#threat-rationale').fill('Requires input validation countermeasures')
    await page.locator('[role="dialog"]').getByRole('button', { name: 'Save' }).click()

    await expect(page.locator('text=Mitigate').first()).toBeVisible()

    // ---- Save ----
    await page.getByRole('button', { name: 'Save' }).first().click()
    await expect(page.locator('text=Save Diagram')).toBeVisible()
    await page.locator('#save-filename').fill('banking-threat-model')

    const downloadPromise = page.waitForEvent('download')
    await page.getByRole('button', { name: 'Download' }).click()
    const download = await downloadPromise
    const savedFilePath = await download.path()

    // ---- Reimport into a fresh guest editor ----
    await page.goto(GUEST_URL)
    await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

    const fileChooserPromise = page.waitForEvent('filechooser')
    await page.getByRole('button', { name: 'Open' }).click()
    const fileChooser = await fileChooserPromise
    await fileChooser.setFiles(savedFilePath!)

    // ---- Verify roundtrip ----
    await expect(page.locator('text=Mobile User').first()).toBeVisible({ timeout: 5_000 })
    await expect(page.locator('text=API Server').first()).toBeVisible({ timeout: 5_000 })
    await expect(page.locator('text=Account DB').first()).toBeVisible({ timeout: 5_000 })

    // System context survived
    await page.getByRole('button', { name: 'Add / Edit Context' }).click()
    await expect(page.locator('#facilitator')).toHaveValue('Security Team')
    await page.getByRole('button', { name: 'System' }).click()
    await expect(page.locator('#system-description')).toHaveValue('Mobile banking application')
    await page.keyboard.press('Escape')

    // Threats survived
    await page.getByRole('button', { name: 'Analyze Threats' }).click()
    await page.waitForURL('**/guest/threats')
    await page.locator('text=API Server').first().click()
    await expect(page.locator('text=SQL Injection')).toBeVisible({ timeout: 5_000 })
    await expect(page.locator('text=Mitigate').first()).toBeVisible()

    // Countermeasure survived
    await page.locator('text=SQL Injection').click()
    await expect(page.locator('text=Input Validation')).toBeVisible({ timeout: 5_000 })
  })
})
