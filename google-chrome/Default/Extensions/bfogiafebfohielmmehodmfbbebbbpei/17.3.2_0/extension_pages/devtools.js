chrome.devtools.panels.elements.createSidebarPane('Element attributes', function (sidebar) {
  const path = chrome.runtime.getURL('extension_pages/elementAttributes.html')
  sidebar.setPage(path)
})
