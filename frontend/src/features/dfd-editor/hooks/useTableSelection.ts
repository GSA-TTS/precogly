import { useCallback, useRef, useState } from 'react'
import type { TableCellRange } from '../types'

/**
 * Which cells of a table are selected, and the gestures that choose them: click
 * one, drag for a rectangle, click a grip for a whole row or column, arrow keys
 * to step, shift-arrow to extend.
 *
 * Shift-click does not extend, though every spreadsheet has it, and shift-arrow
 * does — the asymmetry is not a decision but a constraint. Shift is React
 * Flow's `selectionKeyCode`, and while it is held a *pointerdown* on a cell
 * never reaches this component; measured on the guest canvas, Alt and Meta get
 * through and Shift does not. *Keydowns* are untouched, so shift-arrow arrives
 * normally. Restoring shift-click means passing `selectionKeyCode={null}` to
 * the ReactFlow in DFDEditor and GuestDFDEditor, which costs the one thing
 * Shift does on that canvas: starting a selection box from on top of a node
 * instead of moving that node.
 *
 * The gesture is two-stage, as it is in Miro. An unselected table drags from
 * anywhere in its body like every other node; only once it is selected does a
 * press on a cell belong to the table, and the table is then moved by dragging
 * a grip instead. TableNode enforces that by putting React Flow's `nodrag`
 * class on the cells only while the node is selected, and calling
 * `beginCellSelection` under the same condition.
 */

/**
 * Pointer travel, in screen pixels, past which a press on a cell is a range
 * drag rather than a click on that one cell.
 *
 * Arbitrary, within the band every drag-versus-click UI uses. Lower and a click
 * from an unsteady hand selects two cells; higher and a deliberate drag stops
 * picking up the next cell until the pointer is well inside it.
 */
export const TABLE_DRAG_THRESHOLD = 3

interface CellRef {
  row: number
  col: number
}

function rangeBetween(a: CellRef, b: CellRef): TableCellRange {
  return {
    top: Math.min(a.row, b.row),
    bottom: Math.max(a.row, b.row),
    left: Math.min(a.col, b.col),
    right: Math.max(a.col, b.col),
  }
}

/**
 * Find the cell under the pointer by asking the DOM, rather than by measuring
 * columns and rows and doing the arithmetic.
 *
 * A row's rendered height is not knowable from the data — `minmax(h, auto)`
 * lets it grow to fit wrapped text — so there is no sum to walk. Hit-testing
 * also gets zoom and pan for free.
 *
 * `elementsFromPoint` rather than `elementFromPoint`: the divider drag strips
 * are `pointer-events-auto` and overlay the cells near every column and row
 * edge, so the topmost element is often a divider. The cell is further down the
 * same stack. The table id is checked because two tables can overlap, and a
 * drag must not run off into the cells of the one underneath.
 */
function cellFromPoint(tableId: string, x: number, y: number): CellRef | null {
  for (const element of document.elementsFromPoint(x, y)) {
    const { tableId: id, tableCell } = (element as HTMLElement).dataset ?? {}
    if (!tableCell || id !== tableId) continue
    const [row, col] = tableCell.split(',').map(Number)
    return { row, col }
  }
  return null
}

export interface TableSelection {
  /** The selected rectangle of cells, or null when nothing is selected. */
  range: TableCellRange | null
  /**
   * Which axis the range covers, set only when it came from a grip.
   *
   * This is what lets Delete remove a row or column rather than clear cells.
   * Deriving it from the range instead — one spanning every column is a row —
   * breaks in a one-column table, where every single-cell selection spans every
   * column too, and Delete would take the whole row out.
   */
  axis: 'row' | 'column' | null
  /** Press on a cell. Only called while the table node is already selected. */
  beginCellSelection: (row: number, col: number, event: React.PointerEvent) => void
  /** Select a whole row or column, as clicking its grip does. */
  selectAxis: (axis: 'row' | 'column', index: number) => void
  /**
   * Move the selection onto one cell unless it already covers it, so a
   * right-click acts on what was clicked. Sheets and Excel both do this: a
   * right-click inside a selection keeps it, one outside replaces it.
   */
  selectUnlessInside: (row: number, col: number) => void
  /**
   * Step the selection one cell. Without `extend` the range collapses onto
   * wherever it lands; with it, the range grows or shrinks between the anchor
   * and the cell stepped to, which is what shift-arrow does in a spreadsheet.
   *
   * Returns false when there is nothing selected to move, which is what lets
   * the caller leave the key to React Flow — with no cell selected an arrow
   * still nudges the table itself, as it does for every other node. A step into
   * the table's edge is still a move: it stays put and keeps the key, rather
   * than letting the table lurch sideways at the end of a column.
   */
  moveFocus: (rowDelta: number, colDelta: number, extend?: boolean) => boolean
  clear: () => void
}

export function useTableSelection(
  tableId: string,
  rowCount: number,
  columnCount: number,
  /**
   * Maps any cell to the merge anchor covering it, or to itself. Without it an
   * arrow key would step onto a cell hidden under a merge, which renders
   * nothing, and the selection would appear to vanish mid-table.
   */
  anchorOf: (row: number, col: number) => CellRef = (row, col) => ({ row, col })
): TableSelection {
  const [range, setRange] = useState<TableCellRange | null>(null)
  const [axis, setAxis] = useState<'row' | 'column' | null>(null)

  // The two corners `range` is the rectangle between. `focus` is the end that
  // moves — where a drag finished, and where an arrow key steps from; `anchor`
  // is the end that stays put while shift-arrow grows the selection away from
  // it. Refs because nothing renders from them: the highlight comes from
  // `range`, which is kept in step with every write to either.
  const anchorRef = useRef<CellRef | null>(null)
  const focusRef = useRef<CellRef | null>(null)

  const clear = useCallback(() => {
    setRange(null)
    setAxis(null)
    anchorRef.current = null
    focusRef.current = null
  }, [])

  const selectAxis = useCallback(
    (which: 'row' | 'column', index: number) => {
      // Focus on the axis's first cell, anchor on its last. A plain arrow then
      // steps from the top or left end, which is where Sheets leaves the active
      // cell after a header click, and a shift-arrow sideways widens the
      // selection to two whole columns or rows rather than collapsing it.
      focusRef.current = which === 'column' ? { row: 0, col: index } : { row: index, col: 0 }
      anchorRef.current =
        which === 'column' ? { row: rowCount - 1, col: index } : { row: index, col: columnCount - 1 }
      setAxis(which)
      setRange(
        which === 'column'
          ? { top: 0, bottom: rowCount - 1, left: index, right: index }
          : { top: index, bottom: index, left: 0, right: columnCount - 1 }
      )
    },
    [columnCount, rowCount]
  )

  const selectUnlessInside = useCallback((row: number, col: number) => {
    setRange((current) => {
      if (
        current &&
        row >= current.top &&
        row <= current.bottom &&
        col >= current.left &&
        col <= current.right
      ) {
        return current
      }
      anchorRef.current = { row, col }
      focusRef.current = { row, col }
      setAxis(null)
      return { top: row, bottom: row, left: col, right: col }
    })
  }, [])

  const beginCellSelection = useCallback(
    (row: number, col: number, event: React.PointerEvent) => {
      // Right-click opens the context menu and must not start a selection drag;
      // the menu's own trigger has already handled it.
      if (event.button !== 0) return

      // No `stopPropagation` here, deliberately. React's stops the native event
      // at the root container, and Radix dismisses layers from a `pointerdown`
      // on `document` above it, so a stop leaves an open context menu open.
      //
      // Nothing needs one: `nodrag` on a selected table's cells stops the drag,
      // and no ancestor handles `pointerdown` (@xyflow/react 12.10.0 — its only
      // React-level one is on `Handle`, a descendant; the pane's is capture).

      // The pressed cell is both the selection and the corner a drag grows from.
      const anchor = { row, col }
      anchorRef.current = anchor
      focusRef.current = anchor
      setAxis(null)
      setRange({ top: row, bottom: row, left: col, right: col })

      const startX = event.clientX
      const startY = event.clientY
      let dragging = false

      const handleMove = (moveEvent: PointerEvent) => {
        if (
          !dragging &&
          Math.abs(moveEvent.clientX - startX) < TABLE_DRAG_THRESHOLD &&
          Math.abs(moveEvent.clientY - startY) < TABLE_DRAG_THRESHOLD
        ) {
          return
        }
        dragging = true

        // No cell under the pointer means it has left the table. The range
        // keeps its last value rather than collapsing, so drifting off an edge
        // mid-drag and coming back does not lose the selection.
        const over = cellFromPoint(tableId, moveEvent.clientX, moveEvent.clientY)
        if (!over) return
        focusRef.current = over
        setRange(rangeBetween(anchor, over))
      }

      const handleUp = () => {
        window.removeEventListener('pointermove', handleMove)
        window.removeEventListener('pointerup', handleUp)
      }

      window.addEventListener('pointermove', handleMove)
      window.addEventListener('pointerup', handleUp)
    },
    [tableId]
  )

  const moveFocus = useCallback(
    (rowDelta: number, colDelta: number, extend = false) => {
      const from = focusRef.current
      if (!from) return false

      const clamp = (cell: CellRef) => ({
        row: Math.min(rowCount - 1, Math.max(0, cell.row)),
        col: Math.min(columnCount - 1, Math.max(0, cell.col)),
      })

      // Step out of the block the focus is standing on, rather than one cell:
      // a merge two columns wide would otherwise take two presses to leave, the
      // first landing on a covered cell that renders nothing.
      const leaving = anchorOf(from.row, from.col)
      let step = clamp({ row: from.row + rowDelta, col: from.col + colDelta })
      for (let guard = 0; guard < rowCount + columnCount; guard++) {
        const under = anchorOf(step.row, step.col)
        if (under.row !== leaving.row || under.col !== leaving.col) break
        const next = clamp({ row: step.row + rowDelta, col: step.col + colDelta })
        if (next.row === step.row && next.col === step.col) break
        step = next
      }

      const focus = anchorOf(step.row, step.col)
      focusRef.current = focus

      // Extending keeps the anchor and redraws between it and the new focus, so
      // reversing direction shrinks the selection back through itself the way
      // it does in a spreadsheet, rather than only ever growing.
      const anchor = extend ? (anchorRef.current ?? focus) : focus
      anchorRef.current = anchor

      // A grip's `axis` says Delete may remove that whole row or column. Once
      // an arrow has moved or widened the selection it no longer covers exactly
      // one, so the claim is dropped rather than left to delete the wrong thing.
      setAxis(null)
      setRange(rangeBetween(anchor, focus))
      return true
    },
    [anchorOf, columnCount, rowCount]
  )

  return { range, axis, beginCellSelection, selectAxis, selectUnlessInside, moveFocus, clear }
}
