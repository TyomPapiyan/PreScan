"""QAbstractListModel adapters exposing engine data to QML.

The UI layer is the only place Qt is imported (§10.1). These models turn plain
dicts (built from core dataclasses in the bridge) into role-based list models the
QML views bind to.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import (
    QAbstractListModel,
    QByteArray,
    QModelIndex,
    QPersistentModelIndex,
    Qt,
)

_Index = QModelIndex | QPersistentModelIndex
_ROOT = QModelIndex()


class DictListModel(QAbstractListModel):
    """A list model over a list of dicts, one role per given key."""

    def __init__(self, roles: list[str], parent: Any | None = None) -> None:
        super().__init__(parent)
        self._rows: list[dict[str, Any]] = []
        # Custom roles start after Qt.UserRole.
        self._role_names = {Qt.ItemDataRole.UserRole + i: key for i, key in enumerate(roles)}

    def roleNames(self) -> dict[int, QByteArray]:
        return {role: QByteArray(key.encode()) for role, key in self._role_names.items()}

    def rowCount(self, parent: _Index = _ROOT) -> int:
        if parent.isValid():
            return 0
        return len(self._rows)

    def data(self, index: _Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not 0 <= index.row() < len(self._rows):
            return None
        key = self._role_names.get(role)
        if key is None:
            return None
        return self._rows[index.row()].get(key)

    def replace(self, rows: list[dict[str, Any]]) -> None:
        """Reset the model to a new list of rows."""
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def upsert(self, key_field: str, row: dict[str, Any]) -> None:
        """Insert or update a row identified by row[key_field] (live progress)."""
        key = row.get(key_field)
        for i, existing in enumerate(self._rows):
            if existing.get(key_field) == key:
                self._rows[i] = row
                idx = self.index(i, 0)
                self.dataChanged.emit(idx, idx, list(self._role_names))
                return
        self.beginInsertRows(QModelIndex(), len(self._rows), len(self._rows))
        self._rows.append(row)
        self.endInsertRows()

    def clear(self) -> None:
        self.replace([])
