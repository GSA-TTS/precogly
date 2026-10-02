import { useCallback, useState } from 'react'
import { useReactFlow } from '@xyflow/react'
import {
  TABLE_DEFAULT_FONT_SIZE,
  TABLE_MIN_COLUMN_WIDTH,
  TABLE_MIN_FONT_SIZE,
  TABLE_MIN_ROW_HEIGHT,
  type DiagramNode,
  type TableNodeData,
} from '../types'

export type TableCorner = 'nw' | 'ne' | 'se' | 'sw'

interface TableDrag {
  /** Column widths to render: the drag's live values while one is in progress. */
  columnWidths: number[]
  /** Row heights to render. Floors: a row grows past its stored height to fit text. */
  rowHeights: number[]
  fontSize: number
  /** Visual offset while a top or left corner drag is moving the node's origin. */
  draftOffset: { x: number; y: number } | null
  /** Drag the trailing edge of one column or row. */
  beginResize: (axis: 'column' | 'row', index: number, event: React.PointerEvent) => void
  /** Drag a corner to scale every column and row at once. */
  beginScale: (corner: TableCorner, event: React.PointerEvent) => void
}

/**
 * The two pointer gestures that resize a table: dragging one divider, and
 * dragging a corner to scale the whole thing.
 *
 * Both hold sizes locally for the duration of the drag and write to the graph
 * once on pointerup. Writing each `pointermove` would rewrite every node in the
 * diagram per frame and push one undo entry per pixel. Both also divide pointer
 * deltas by the canvas zoom: a drag is measured in screen pixels while sizes
 * are stored in diagram coordinates, so at 50% zoom the data moves twice as far
 * as the cursor did.
 */
export function useTableDrag(id: string, data: TableNodeData): TableDrag {
  const { setNodes, getZoom } = useReactFlow<DiagramNode>()

  const [draftSizes, setDraftSizes] = useState<{
    columnWidths: number[]
    rowHeights: number[]
    fontSize?: number
  } | null>(null)

  /**
   * Growing from a top or left corner moves the node's origin, but writing
   * `node.position` on every frame has the same per-pixel undo problem as the
   * sizes. So the node is translated visually during the drag and its real
   * position is written once on pointerup.
   */
  const [draftOffset, setDraftOffset] = useState<{ x: number; y: number } | null>(null)

  const beginResize = useCallback(
    (axis: 'column' | 'row', index: number, event: React.PointerEvent) => {
      event.stopPropagation()
      event.preventDefault()

      const startCoord = axis === 'column' ? event.clientX : event.clientY
      const startColumnWidths = [...data.columnWidths]
      const startRowHeights = data.rows.map((row) => row.height)
      const zoom = getZoom()

      let latest = { columnWidths: startColumnWidths, rowHeights: startRowHeights }

      const handleMove = (moveEvent: PointerEvent) => {
        const delta =
          ((axis === 'column' ? moveEvent.clientX : moveEvent.clientY) - startCoord) / zoom
        latest =
          axis === 'column'
            ? {
                columnWidths: startColumnWidths.map((width, ci) =>
                  ci === index ? Math.max(TABLE_MIN_COLUMN_WIDTH, width + delta) : width
                ),
                rowHeights: startRowHeights,
              }
            : {
                columnWidths: startColumnWidths,
                rowHeights: startRowHeights.map((height, ri) =>
                  ri === index ? Math.max(TABLE_MIN_ROW_HEIGHT, height + delta) : height
                ),
              }
        setDraftSizes(latest)
      }

      const handleUp = () => {
        window.removeEventListener('pointermove', handleMove)
        window.removeEventListener('pointerup', handleUp)
        setDraftSizes(null)
        setNodes((nodes) =>
          nodes.map((node) =>
            node.id === id
              ? {
                  ...node,
                  data: {
                    ...node.data,
                    columnWidths: latest.columnWidths,
                    rows: (node.data as TableNodeData).rows.map((row, ri) => ({
                      ...row,
                      height: latest.rowHeights[ri],
                    })),
                  },
                }
              : node
          )
        )
      }

      window.addEventListener('pointermove', handleMove)
      window.addEventListener('pointerup', handleUp)
    },
    [data.columnWidths, data.rows, getZoom, id, setNodes]
  )

  /**
   * Scales every column and row by one factor per axis, so the table grows as a
   * whole and keeps its proportions. Dragging a left or top corner also moves
   * the node's origin, since the opposite edge is what stays put.
   *
   * The floor is one minimum-width column per column, clamped on the total
   * rather than per column: clamping each separately would distort the
   * proportions as soon as any single column hit the floor.
   */
  const beginScale = useCallback(
    (corner: TableCorner, event: React.PointerEvent) => {
      event.stopPropagation()
      event.preventDefault()

      const startX = event.clientX
      const startY = event.clientY
      const startColumnWidths = [...data.columnWidths]
      const startRowHeights = data.rows.map((row) => row.height)
      const startWidth = startColumnWidths.reduce((sum, width) => sum + width, 0)
      const startHeight = startRowHeights.reduce((sum, height) => sum + height, 0)
      const minWidth = startColumnWidths.length * TABLE_MIN_COLUMN_WIDTH
      const minHeight = startRowHeights.length * TABLE_MIN_ROW_HEIGHT
      const startFontSize = data.fontSize ?? TABLE_DEFAULT_FONT_SIZE
      const zoom = getZoom()

      const growsLeft = corner === 'nw' || corner === 'sw'
      const growsUp = corner === 'nw' || corner === 'ne'

      let latestSizes = { columnWidths: startColumnWidths, rowHeights: startRowHeights }
      let latestOffset = { x: 0, y: 0 }
      let latestFontSize = startFontSize

      const handleMove = (moveEvent: PointerEvent) => {
        const dx = (moveEvent.clientX - startX) / zoom
        const dy = (moveEvent.clientY - startY) / zoom

        let width = Math.max(minWidth, growsLeft ? startWidth - dx : startWidth + dx)
        let height = Math.max(minHeight, growsUp ? startHeight - dy : startHeight + dy)

        // Shift scales uniformly and takes the text with it, as Miro does; a
        // plain drag stretches the axes independently and leaves text alone.
        // Read per move rather than at pointerdown, so shift can be pressed or
        // released mid-drag.
        if (moveEvent.shiftKey) {
          const uniform = Math.max(width / startWidth, height / startHeight)
          width = Math.max(minWidth, startWidth * uniform)
          height = Math.max(minHeight, startHeight * uniform)
          latestFontSize = Math.max(TABLE_MIN_FONT_SIZE, startFontSize * uniform)
        } else {
          latestFontSize = startFontSize
        }

        const scaleX = width / startWidth
        const scaleY = height / startHeight

        latestSizes = {
          columnWidths: startColumnWidths.map((columnWidth) => columnWidth * scaleX),
          rowHeights: startRowHeights.map((rowHeight) => rowHeight * scaleY),
        }
        // Derived from the clamped size rather than the raw pointer delta, so a
        // drag past the minimum stops moving the node instead of sliding it.
        latestOffset = {
          x: growsLeft ? startWidth - width : 0,
          y: growsUp ? startHeight - height : 0,
        }

        setDraftSizes({ ...latestSizes, fontSize: latestFontSize })
        setDraftOffset(latestOffset)
      }

      const handleUp = () => {
        window.removeEventListener('pointermove', handleMove)
        window.removeEventListener('pointerup', handleUp)
        setDraftSizes(null)
        setDraftOffset(null)
        setNodes((nodes) =>
          nodes.map((node) =>
            node.id === id
              ? {
                  ...node,
                  position: {
                    x: node.position.x + latestOffset.x,
                    y: node.position.y + latestOffset.y,
                  },
                  data: {
                    ...node.data,
                    columnWidths: latestSizes.columnWidths,
                    fontSize: latestFontSize,
                    rows: (node.data as TableNodeData).rows.map((row, ri) => ({
                      ...row,
                      height: latestSizes.rowHeights[ri],
                    })),
                  },
                }
              : node
          )
        )
      }

      window.addEventListener('pointermove', handleMove)
      window.addEventListener('pointerup', handleUp)
    },
    [data.columnWidths, data.fontSize, data.rows, getZoom, id, setNodes]
  )

  return {
    columnWidths: draftSizes?.columnWidths ?? data.columnWidths,
    rowHeights: draftSizes?.rowHeights ?? data.rows.map((row) => row.height),
    fontSize: draftSizes?.fontSize ?? data.fontSize ?? TABLE_DEFAULT_FONT_SIZE,
    draftOffset,
    beginResize,
    beginScale,
  }
}
