import QtQuick

// Reusable drag-and-drop target; emits fileDropped(url) with the first file.
DropArea {
    id: zone
    signal fileDropped(string url)
    onDropped: (drop) => {
        if (drop.hasUrls && drop.urls.length > 0)
            zone.fileDropped(drop.urls[0].toString())
    }
}
