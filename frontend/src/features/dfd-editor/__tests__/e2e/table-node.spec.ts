import { test, expect, type Page } from '@playwright/test'

/**
 * The table node's pointer gestures, which are the part of it no type check or
 * unit test can reach: whether a press lands on the table or on React Flow's
 * node drag depends on real event propagation.
 *
 * Driven through the guest editor because it runs with no backend.
 */

const GUEST_URL = '/guest'

/** Drop a `columns` x `rows` table on the canvas and return its cells' locator. */
async function insertTable(page: Page, columns: number, rows: number) {
  await page.goto(GUEST_URL)
  await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

  // A table's size is chosen before it exists, so the palette item opens a grid
  // picker rather than placing one directly.
  await page.getByText('Table', { exact: true }).click()
  await page.getByRole('button', { name: `${columns} by ${rows}` }).click()

  const cells = page.locator('[data-table-cell]')
  await expect(cells).toHaveCount(columns * rows)
  return cells
}

const cell = (page: Page, row: number, col: number) =>
  page.locator(`[data-table-cell="${row},${col}"]`)

/** Which cells currently carry the selection overlay, as "row,col" strings. */
const selectedCells = (page: Page) =>
  page.evaluate(() =>
    Array.from(document.querySelectorAll('[data-table-cell]'))
      .filter((c) => c.querySelector('div.absolute.inset-0'))
      .map((c) => (c as HTMLElement).dataset.tableCell)
  )

test('an unselected table still drags from its body', async ({ page }) => {
  await insertTable(page, 3, 3)

  // Click elsewhere so the table is not selected, which is the state in which a
  // press on a cell belongs to React Flow rather than to the table.
  await page.locator('.react-flow__pane').click({ position: { x: 40, y: 40 } })

  const before = await cell(page, 1, 1).boundingBox()
  if (!before) throw new Error('table cells are not laid out')

  await page.mouse.move(before.x + before.width / 2, before.y + before.height / 2)
  await page.mouse.down()
  await page.mouse.move(before.x + before.width / 2 + 80, before.y + before.height / 2 + 60, {
    steps: 10,
  })
  await page.mouse.up()

  const after = await cell(page, 1, 1).boundingBox()
  if (!after) throw new Error('table cells are not laid out')
  expect(after.x - before.x).toBeGreaterThan(50)
  expect(after.y - before.y).toBeGreaterThan(30)
})

test('a selected table moves from its grip, not its cells', async ({ page }) => {
  await insertTable(page, 3, 3)

  await cell(page, 1, 1).click()
  const before = await cell(page, 1, 1).boundingBox()
  if (!before) throw new Error('table cells are not laid out')

  const grip = await page.getByTitle('Row 2').boundingBox()
  if (!grip) throw new Error('row grip is not laid out')

  await page.mouse.move(grip.x + grip.width / 2, grip.y + grip.height / 2)
  await page.mouse.down()
  await page.mouse.move(grip.x + grip.width / 2 + 80, grip.y + grip.height / 2, { steps: 10 })
  await page.mouse.up()

  const after = await cell(page, 1, 1).boundingBox()
  if (!after) throw new Error('table cells are not laid out')
  expect(after.x - before.x).toBeGreaterThan(50)
})

test('a click selects one cell, once the table itself is selected', async ({ page }) => {
  await insertTable(page, 3, 3)

  // The first click lands on React Flow and selects the node; only then do the
  // cells take the pointer.
  await cell(page, 1, 1).click()
  expect(await selectedCells(page)).toEqual([])

  await cell(page, 1, 1).click()
  expect(await selectedCells(page)).toEqual(['1,1'])

  await cell(page, 2, 0).click()
  expect(await selectedCells(page)).toEqual(['2,0'])
})

test('a drag selects the rectangle between its ends', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 0, 0).click()

  const from = (await cell(page, 2, 2).boundingBox())!
  const to = (await cell(page, 1, 1).boundingBox())!

  // Dragged up and to the left, so the range has to normalize rather than
  // depending on which corner came first.
  await page.mouse.move(from.x + from.width / 2, from.y + from.height / 2)
  await page.mouse.down()
  await page.mouse.move(to.x + to.width / 2, to.y + to.height / 2, { steps: 10 })
  await page.mouse.up()

  expect(await selectedCells(page)).toEqual(['1,1', '1,2', '2,1', '2,2'])
})

test('a grip selects its whole row or column', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 1, 1).click()

  await page.getByTitle('Column 2').click()
  expect(await selectedCells(page)).toEqual(['0,1', '1,1', '2,1'])

  await page.getByTitle('Row 3').click()
  expect(await selectedCells(page)).toEqual(['2,0', '2,1', '2,2'])
})

test('deselecting the table drops the cell selection with it', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 1, 1).click()
  await cell(page, 1, 1).click()
  expect(await selectedCells(page)).toEqual(['1,1'])

  await page.locator('.react-flow__pane').click({ position: { x: 40, y: 40 } })
  expect(await selectedCells(page)).toEqual([])
})

test('a press on a cell dismisses the context menu, and still selects', async ({ page }) => {
  await insertTable(page, 3, 3)

  // The menu is drawn down-right of the press and Playwright will not click a
  // cell it covers, so open at the last cell and dismiss from the first.
  await cell(page, 2, 2).click()
  await cell(page, 2, 2).click({ button: 'right' })
  await expect(page.getByRole('menu')).toBeVisible()

  // Radix dismisses from a `pointerdown` on `document`, so a cell that stops
  // propagation leaves the menu open. Only a selected table takes the pointer,
  // which is why the bug needed one: on an unselected table the menu closed.
  await cell(page, 0, 0).click()
  await expect(page.getByRole('menu')).toBeHidden()

  // Letting the press through to `document` must not hand it back to React Flow.
  expect(await selectedCells(page)).toEqual(['0,0'])
})

test('fills one cell from its context menu', async ({ page }) => {
  await insertTable(page, 3, 3)

  await cell(page, 1, 1).click()
  await cell(page, 1, 1).click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Fill' }).click()
  await page.getByRole('menuitemradio', { name: 'Green' }).click()

  await expect(cell(page, 1, 1)).toHaveCSS('background-color', 'rgb(220, 252, 231)')
  // Its neighbours are untouched.
  await expect(cell(page, 1, 2)).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)')
})

test('fills a dragged range of cells', async ({ page }) => {
  await insertTable(page, 3, 3)

  // First click selects the node; the table's cells only take the pointer once
  // the node is selected, so the drag below needs this.
  await cell(page, 1, 0).click()

  const from = await cell(page, 1, 0).boundingBox()
  const to = await cell(page, 2, 1).boundingBox()
  if (!from || !to) throw new Error('table cells are not laid out')

  await page.mouse.move(from.x + from.width / 2, from.y + from.height / 2)
  await page.mouse.down()
  await page.mouse.move(to.x + to.width / 2, to.y + to.height / 2, { steps: 10 })
  await page.mouse.up()

  await cell(page, 2, 1).click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Fill' }).click()
  await page.getByRole('menuitemradio', { name: 'Blue' }).click()

  for (const [row, col] of [[1, 0], [1, 1], [2, 0], [2, 1]]) {
    await expect(cell(page, row, col)).toHaveCSS('background-color', 'rgb(219, 234, 254)')
  }
  await expect(cell(page, 0, 0)).not.toHaveCSS('background-color', 'rgb(219, 234, 254)')
})

test('fills a whole column from its grip', async ({ page }) => {
  await insertTable(page, 3, 3)

  await cell(page, 1, 1).click()
  await page.getByTitle('Column 2').click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Fill' }).click()
  await page.getByRole('menuitemradio', { name: 'Pink' }).click()

  for (const row of [0, 1, 2]) {
    await expect(cell(page, row, 1)).toHaveCSS('background-color', 'rgb(252, 231, 243)')
  }
})

test('a filled cell is still editable, and keeps its fill', async ({ page }) => {
  await insertTable(page, 3, 3)

  await cell(page, 1, 1).click()
  await cell(page, 1, 1).click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Fill' }).click()
  await page.getByRole('menuitemradio', { name: 'Yellow' }).click()

  // Two things at once. `nodrag` sits on a selected table's cells so a press
  // starts a selection rather than a node drag, and a double-click still has to
  // open the editor through it. And the editor has to keep focus: Radix returns
  // focus to the menu's trigger after the close animation, which used to land
  // on the textarea a beat after it opened and pull the caret out of it.
  await cell(page, 1, 1).dblclick()
  await expect(cell(page, 1, 1).locator('textarea')).toBeFocused()
  await page.keyboard.type('Payments')
  await page.waitForTimeout(400)
  await expect(cell(page, 1, 1).locator('textarea')).toBeFocused()
  await page.keyboard.press('Escape')

  await expect(cell(page, 1, 1)).toContainText('Payments')
  await expect(cell(page, 1, 1)).toHaveCSS('background-color', 'rgb(254, 249, 195)')
})

/** Fill one cell, assuming the table node is already selected. */
async function fill(page: Page, row: number, col: number, colour: string) {
  await cell(page, row, col).click()
  await cell(page, row, col).click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Fill' }).click()
  await page.getByRole('menuitemradio', { name: colour, exact: true }).click()
}

test('offers the eight colours every comparable tool has', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 1, 1).click()
  await cell(page, 1, 1).click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Fill' }).click()

  for (const name of ['No fill', 'Gray', 'Red', 'Orange', 'Yellow', 'Green', 'Blue', 'Purple', 'Pink']) {
    await expect(page.getByRole('menuitemradio', { name, exact: true })).toHaveCount(1)
  }
})

test('a fill overrides the header row tint, gray included', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 0, 0).click()

  // The header's tint comes from a Tailwind class, so its exact value is
  // whatever the installed version resolves slate-100 to — v4 renders it in
  // oklch. The fills are hardcoded hexes. So compare the two rather than
  // pinning the header's value, which a Tailwind upgrade would move.
  const headerTint = await cell(page, 0, 2).evaluate(
    (el) => getComputedStyle(el).backgroundColor
  )

  // Gray sits a step darker than the header precisely so that filling a header
  // cell gray is visible rather than a no-op.
  await fill(page, 0, 0, 'Gray')
  await expect(cell(page, 0, 0)).toHaveCSS('background-color', 'rgb(226, 232, 240)')
  expect(await cell(page, 0, 0).evaluate((el) => getComputedStyle(el).backgroundColor)).not.toBe(
    headerTint
  )

  await fill(page, 0, 1, 'Red')
  await expect(cell(page, 0, 1)).toHaveCSS('background-color', 'rgb(254, 226, 226)')

  await fill(page, 1, 0, 'Purple')
  await expect(cell(page, 1, 0)).toHaveCSS('background-color', 'rgb(243, 232, 255)')
})

test('arrow keys walk the selection, not the table', async ({ page }) => {
  await insertTable(page, 3, 3)

  await cell(page, 1, 1).click()
  await cell(page, 1, 1).click()
  expect(await selectedCells(page)).toEqual(['1,1'])

  const before = (await cell(page, 1, 1).boundingBox())!

  await page.keyboard.press('ArrowRight')
  expect(await selectedCells(page)).toEqual(['1,2'])
  await page.keyboard.press('ArrowDown')
  expect(await selectedCells(page)).toEqual(['2,2'])
  await page.keyboard.press('ArrowLeft')
  await page.keyboard.press('ArrowUp')
  expect(await selectedCells(page)).toEqual(['1,1'])

  // The table itself has not budged. Before this the arrows reached React
  // Flow, which nudges the selected node a few pixels per press.
  const after = (await cell(page, 1, 1).boundingBox())!
  expect(Math.round(after.x - before.x)).toBe(0)
  expect(Math.round(after.y - before.y)).toBe(0)
})

test('arrow keys stop at the table edge', async ({ page }) => {
  await insertTable(page, 3, 3)

  await cell(page, 0, 0).click()
  await cell(page, 0, 0).click()
  const before = (await cell(page, 0, 0).boundingBox())!

  // Pressing into the edge holds the selection still and keeps the key, rather
  // than letting it fall through and slide the table off to the left.
  await page.keyboard.press('ArrowLeft')
  await page.keyboard.press('ArrowLeft')
  await page.keyboard.press('ArrowUp')
  expect(await selectedCells(page)).toEqual(['0,0'])

  const after = (await cell(page, 0, 0).boundingBox())!
  expect(Math.round(after.x - before.x)).toBe(0)
  expect(Math.round(after.y - before.y)).toBe(0)
})

test('an arrow key collapses a dragged range onto one cell', async ({ page }) => {
  await insertTable(page, 3, 3)

  await cell(page, 0, 0).click()
  const from = (await cell(page, 0, 0).boundingBox())!
  const to = (await cell(page, 1, 1).boundingBox())!
  await page.mouse.move(from.x + from.width / 2, from.y + from.height / 2)
  await page.mouse.down()
  await page.mouse.move(to.x + to.width / 2, to.y + to.height / 2, { steps: 10 })
  await page.mouse.up()
  expect(await selectedCells(page)).toEqual(['0,0', '0,1', '1,0', '1,1'])

  // It steps from where the drag ended, not from the rectangle's top left.
  await page.keyboard.press('ArrowRight')
  expect(await selectedCells(page)).toEqual(['1,2'])
})

test('with no cell selected the arrows still nudge the table', async ({ page }) => {
  await insertTable(page, 3, 3)

  // Selected as a node, but no cell picked: the arrows belong to React Flow.
  await cell(page, 1, 1).click()
  const before = (await cell(page, 1, 1).boundingBox())!

  await page.keyboard.press('ArrowRight')
  await page.keyboard.press('ArrowRight')
  const after = (await cell(page, 1, 1).boundingBox())!

  expect(after.x - before.x).toBeGreaterThan(0)
  expect(await selectedCells(page)).toEqual([])
})

test('shift-arrow extends the selection, and reversing shrinks it', async ({ page }) => {
  await insertTable(page, 3, 3)

  await cell(page, 1, 1).click()
  await cell(page, 1, 1).click()

  await page.keyboard.press('Shift+ArrowRight')
  expect(await selectedCells(page)).toEqual(['1,1', '1,2'])

  await page.keyboard.press('Shift+ArrowDown')
  expect(await selectedCells(page)).toEqual(['1,1', '1,2', '2,1', '2,2'])

  // Back the way it came: the anchor stays on 1,1, so the rectangle shrinks
  // rather than only ever growing.
  await page.keyboard.press('Shift+ArrowUp')
  expect(await selectedCells(page)).toEqual(['1,1', '1,2'])
  await page.keyboard.press('Shift+ArrowLeft')
  expect(await selectedCells(page)).toEqual(['1,1'])

  // And through itself, to the other side of the anchor.
  await page.keyboard.press('Shift+ArrowLeft')
  expect(await selectedCells(page)).toEqual(['1,0', '1,1'])
})

test('shift-arrow can fill a block, and a plain arrow collapses it again', async ({ page }) => {
  await insertTable(page, 3, 3)

  await cell(page, 0, 0).click()
  await cell(page, 0, 0).click()
  await page.keyboard.press('Shift+ArrowRight')
  await page.keyboard.press('Shift+ArrowDown')

  await cell(page, 1, 1).click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Fill' }).click()
  await page.getByRole('menuitemradio', { name: 'Red', exact: true }).click()

  for (const [row, col] of [[0, 0], [0, 1], [1, 0], [1, 1]]) {
    await expect(cell(page, row, col)).toHaveCSS('background-color', 'rgb(254, 226, 226)')
  }

  await page.keyboard.press('ArrowRight')
  expect(await selectedCells(page)).toEqual(['1,2'])
})

test('shift-arrow from a column grip widens to two whole columns', async ({ page }) => {
  await insertTable(page, 3, 3)

  await cell(page, 1, 1).click()
  await page.getByTitle('Column 1').click()
  expect(await selectedCells(page)).toEqual(['0,0', '1,0', '2,0'])

  // The grip anchors at the far end of the axis, so sideways widens rather
  // than collapsing the column to one cell.
  await page.keyboard.press('Shift+ArrowRight')
  expect(await selectedCells(page)).toEqual(['0,0', '0,1', '1,0', '1,1', '2,0', '2,1'])
})

test('shift-arrow stops at the table edge without moving it', async ({ page }) => {
  await insertTable(page, 3, 3)

  await cell(page, 0, 0).click()
  await cell(page, 0, 0).click()
  const before = (await cell(page, 0, 0).boundingBox())!

  await page.keyboard.press('Shift+ArrowUp')
  await page.keyboard.press('Shift+ArrowLeft')
  expect(await selectedCells(page)).toEqual(['0,0'])

  // React Flow nudges a node further on shift+arrow than on a plain arrow, so
  // an unhandled one here would be doubly visible.
  const after = (await cell(page, 0, 0).boundingBox())!
  expect(Math.round(after.x - before.x)).toBe(0)
  expect(Math.round(after.y - before.y)).toBe(0)
})

/** Open the fill submenu on a cell and read back which swatch is marked current. */
async function openFillMenu(page: Page, row: number, col: number) {
  await cell(page, row, col).click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Fill' }).click()
  return page.getByRole('menuitemradio', { checked: true })
}

test('the picker opens showing the fill the cell already has', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 0, 0).click()

  // An unfilled cell reads as "No fill", which is a real answer and not the
  // same as nothing being marked.
  await expect(await openFillMenu(page, 1, 1)).toHaveAccessibleName('No fill')
  await page.keyboard.press('Escape')
  await page.keyboard.press('Escape')

  await fill(page, 1, 1, 'Green')
  await expect(await openFillMenu(page, 1, 1)).toHaveAccessibleName('Green')
  await page.keyboard.press('Escape')
  await page.keyboard.press('Escape')

  // Recolouring moves the mark rather than leaving the old one set.
  await fill(page, 1, 1, 'Purple')
  await expect(await openFillMenu(page, 1, 1)).toHaveAccessibleName('Purple')
})

test('a selection spanning two fills marks neither', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 0, 0).click()

  await fill(page, 1, 0, 'Red')
  await fill(page, 1, 1, 'Blue')

  // Both cells at once: they disagree, so no swatch claims to be current.
  await cell(page, 1, 0).click()
  await page.keyboard.press('Shift+ArrowRight')
  await cell(page, 1, 1).click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Fill' }).click()
  await expect(page.getByRole('menuitemradio', { checked: true })).toHaveCount(0)
})

test('a whole column of one colour marks that colour', async ({ page }) => {
  await insertTable(page, 3, 3)

  await cell(page, 1, 1).click()
  await page.getByTitle('Column 1').click()
  await page.getByTitle('Column 1').click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Fill' }).click()
  await page.getByRole('menuitemradio', { name: 'Yellow', exact: true }).click()

  await page.getByTitle('Column 1').click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Fill' }).click()
  await expect(page.getByRole('menuitemradio', { checked: true })).toHaveAccessibleName('Yellow')
})

/** Select a rectangle by dragging, assuming the table node is already selected. */
async function dragSelect(page: Page, from: [number, number], to: [number, number]) {
  const a = (await cell(page, from[0], from[1]).boundingBox())!
  const b = (await cell(page, to[0], to[1]).boundingBox())!
  await page.mouse.move(a.x + a.width / 2, a.y + a.height / 2)
  await page.mouse.down()
  await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 10 })
  await page.mouse.up()
}

/**
 * Run a context-menu entry on a cell, then wait for the menu to finish closing.
 *
 * Radix animates the menu out, and until it is detached it still swallows
 * pointer events — a click on a cell straight afterwards lands on the menu.
 */
async function cellMenu(page: Page, row: number, col: number, item: string) {
  await cell(page, row, col).click({ button: 'right' })
  await page.getByRole('menuitem', { name: item, exact: true }).click()
  await expect(page.locator('[data-slot="context-menu-content"]')).toHaveCount(0)
}

/** How many grid tracks a cell spans, read back off its computed style. */
const spanOf = (page: Page, row: number, col: number) =>
  cell(page, row, col).evaluate((el) => {
    const s = getComputedStyle(el)
    return { col: s.gridColumnEnd, row: s.gridRowEnd }
  })

test('merges a selection into one cell that spans its tracks', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 0, 0).click()
  await dragSelect(page, [0, 0], [0, 1])

  await cellMenu(page, 0, 0, 'Merge cells')

  expect(await spanOf(page, 0, 0)).toEqual({ col: 'span 2', row: 'span 1' })
  // The swallowed cell is gone from the DOM, not merely hidden.
  await expect(cell(page, 0, 1)).toHaveCount(0)
  await expect(page.locator('[data-table-cell]')).toHaveCount(8)
})

test('merging keeps the anchor text and discards the rest, undo restores it', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 0, 0).click()

  await cell(page, 0, 0).dblclick()
  await page.keyboard.type('Navigation Apps')
  await page.keyboard.press('Escape')
  await cell(page, 0, 1).dblclick()
  await page.keyboard.type('discard me')
  await page.keyboard.press('Escape')

  await dragSelect(page, [0, 0], [0, 1])
  await cellMenu(page, 0, 0, 'Merge cells')

  // Excel's rule: the upper-left value survives, the others are deleted.
  await expect(cell(page, 0, 0)).toContainText('Navigation Apps')
  await expect(page.locator('[data-table-cell]')).toHaveCount(8)

  // Unlike Excel and Sheets, where the discarded text is gone for good.
  await page.keyboard.press('Control+z')
  await expect(page.locator('[data-table-cell]')).toHaveCount(9)
  await expect(cell(page, 0, 1)).toContainText('discard me')
})

test('unmerge splits the block back into plain cells', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 0, 0).click()
  await dragSelect(page, [0, 0], [1, 1])

  await cellMenu(page, 0, 0, 'Merge cells')
  expect(await spanOf(page, 0, 0)).toEqual({ col: 'span 2', row: 'span 2' })
  await expect(page.locator('[data-table-cell]')).toHaveCount(6)

  await cellMenu(page, 0, 0, 'Unmerge cells')
  expect(await spanOf(page, 0, 0)).toEqual({ col: 'span 1', row: 'span 1' })
  await expect(page.locator('[data-table-cell]')).toHaveCount(9)
})

test('the menu entries are disabled when they have nothing to do', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 1, 1).click()
  await cell(page, 1, 1).click()

  // One unmerged cell: nothing to merge, nothing to split.
  await cell(page, 1, 1).click({ button: 'right' })
  await expect(page.getByRole('menuitem', { name: 'Merge cells', exact: true })).toBeDisabled()
  await expect(page.getByRole('menuitem', { name: 'Unmerge cells', exact: true })).toBeDisabled()
  await page.keyboard.press('Escape')

  await dragSelect(page, [1, 1], [1, 2])
  await cell(page, 1, 1).click({ button: 'right' })
  await expect(page.getByRole('menuitem', { name: 'Merge cells', exact: true })).toBeEnabled()
  await expect(page.getByRole('menuitem', { name: 'Unmerge cells', exact: true })).toBeDisabled()
})

test('an insert through a merge unmerges it', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 0, 0).click()
  await dragSelect(page, [0, 0], [0, 1])
  await cellMenu(page, 0, 0, 'Merge cells')
  expect(await spanOf(page, 0, 0)).toEqual({ col: 'span 2', row: 'span 1' })

  // Excel would expand the selection to the merge and insert two columns;
  // Sheets often refuses outright. Splitting the merge is neither.
  await cell(page, 0, 0).click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Insert column right' }).click()

  await expect(page.locator('[data-table-cell]')).toHaveCount(12)
  expect(await spanOf(page, 0, 0)).toEqual({ col: 'span 1', row: 'span 1' })
})

test('an arrow key steps over a merged block rather than into it', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 0, 0).click()
  await dragSelect(page, [0, 0], [0, 1])
  await cellMenu(page, 0, 0, 'Merge cells')

  await cell(page, 0, 0).click()
  expect(await selectedCells(page)).toEqual(['0,0'])

  // 0,1 is under the merge and renders nothing, so one press has to clear the
  // whole block rather than land on a cell that is not there.
  await page.keyboard.press('ArrowRight')
  expect(await selectedCells(page)).toEqual(['0,2'])

  // Coming back lands on the block, selecting its anchor.
  await page.keyboard.press('ArrowLeft')
  expect(await selectedCells(page)).toEqual(['0,0'])
})

test('a merged cell is clickable through its middle', async ({ page }) => {
  await insertTable(page, 3, 3)
  await cell(page, 0, 0).click()
  await dragSelect(page, [0, 0], [1, 0])
  await cellMenu(page, 0, 0, 'Merge cells')

  // The centre of a two-row-tall merged cell is exactly where the row divider
  // between the rows it swallowed used to sit. Its 7px drag strip spans the
  // whole table, so it took the click and started a resize instead.
  const box = (await cell(page, 0, 0).boundingBox())!
  const heightBefore = box.height
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2)

  expect(await selectedCells(page)).toEqual(['0,0'])
  expect(Math.round((await cell(page, 0, 0).boundingBox())!.height)).toBe(Math.round(heightBefore))
})
