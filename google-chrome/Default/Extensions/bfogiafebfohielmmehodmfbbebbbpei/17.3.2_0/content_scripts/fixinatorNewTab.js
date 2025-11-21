document.getElementById('copyright').innerText +=
  ' ' + new Date().getFullYear().toString() + ' Keeper Security, Inc.'

if (window.safariApi) {
  safari.self.addEventListener('message', function (messageEvent) {
    var message
    try {
      message = JSON.parse(messageEvent.message)
      if (message.name === 'populateFixinatorTab' && message.data) {
        document.getElementById('json').textContent = JSON.stringify(message.data, undefined, 2)
      }
    } catch (err) {
      // Not a message we want anyway
      return
    }
    handler(message)
  })
} else {
  chrome.runtime.onMessage.addListener((msg, sender) => {
    if (msg.name === 'populateFixinatorTab' && msg.data) {
      document.getElementById('json').textContent = JSON.stringify(msg.data, undefined, 2)
    }
  })
}
