.pragma library

function clamp(value, minimum, maximum) {
    return Math.max(minimum, Math.min(value, Math.max(minimum, maximum)))
}

function opposite(position, Position) {
    switch (position) {
    case Position.Top:
        return Position.Bottom
    case Position.Bottom:
        return Position.Top
    case Position.Left:
        return Position.Right
    case Position.Right:
        return Position.Left
    default:
        return position
    }
}

function place(anchor, popupWidth, popupHeight, position, spacing, Position) {
    switch (position) {
    case Position.Top:
        return { x: anchor.x + (anchor.width - popupWidth) / 2, y: anchor.y - popupHeight - spacing }
    case Position.Bottom:
        return { x: anchor.x + (anchor.width - popupWidth) / 2, y: anchor.y + anchor.height + spacing }
    case Position.Left:
        return { x: anchor.x - popupWidth - spacing, y: anchor.y + (anchor.height - popupHeight) / 2 }
    case Position.Right:
        return { x: anchor.x + anchor.width + spacing, y: anchor.y + (anchor.height - popupHeight) / 2 }
    case Position.Center:
        return { x: (anchor.width - popupWidth) / 2, y: (anchor.height - popupHeight) / 2 }
    default:
        return { x: anchor.x, y: anchor.y + anchor.height + spacing }
    }
}

function fits(rect, popupWidth, popupHeight, bounds, margin) {
    return rect.x >= bounds.x + margin
        && rect.y >= bounds.y + margin
        && rect.x + popupWidth <= bounds.x + bounds.width - margin
        && rect.y + popupHeight <= bounds.y + bounds.height - margin
}

function resolve(anchor, popupWidth, popupHeight, bounds, requestedPosition, spacing, margin, Position) {
    var position = requestedPosition === Position.None ? Position.Bottom : requestedPosition
    var candidate = place(anchor, popupWidth, popupHeight, position, spacing, Position)

    if (position !== Position.Center && !fits(candidate, popupWidth, popupHeight, bounds, margin)) {
        var flippedPosition = opposite(position, Position)
        var flipped = place(anchor, popupWidth, popupHeight, flippedPosition, spacing, Position)
        if (fits(flipped, popupWidth, popupHeight, bounds, margin)) {
            position = flippedPosition
            candidate = flipped
        } else {
            var currentVisibleArea = visibleArea(candidate, popupWidth, popupHeight, bounds, margin)
            var flippedVisibleArea = visibleArea(flipped, popupWidth, popupHeight, bounds, margin)
            if (flippedVisibleArea > currentVisibleArea) {
                position = flippedPosition
                candidate = flipped
            }
        }
    }

    candidate.x = clamp(candidate.x, bounds.x + margin, bounds.x + bounds.width - popupWidth - margin)
    candidate.y = clamp(candidate.y, bounds.y + margin, bounds.y + bounds.height - popupHeight - margin)
    return { x: candidate.x, y: candidate.y, position: position }
}

function visibleArea(rect, popupWidth, popupHeight, bounds, margin) {
    var left = Math.max(rect.x, bounds.x + margin)
    var top = Math.max(rect.y, bounds.y + margin)
    var right = Math.min(rect.x + popupWidth, bounds.x + bounds.width - margin)
    var bottom = Math.min(rect.y + popupHeight, bounds.y + bounds.height - margin)
    return Math.max(0, right - left) * Math.max(0, bottom - top)
}
