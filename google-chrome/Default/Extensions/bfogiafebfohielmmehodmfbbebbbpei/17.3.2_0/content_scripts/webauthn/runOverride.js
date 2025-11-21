;(function runNavigatorOverride() {
  'use strict'

  if (!supportsWebauthn()) {
    return
  }

  fireLoad()

  function fireLoad() {
    // Prepare script
    const script = document.createElement('script')
    script.setAttribute('type', 'text/javascript')
    // TODO: use this instead runtimeGetURL for this chrome command
    script.setAttribute('src', chrome.runtime.getURL('content_scripts/webauthn/webauthn.js'))

    // Insert on page
    document.documentElement.prepend(script)
    script.remove()
  }

  function supportsWebauthn() {
    return window.isSecureContext && typeof window.navigator.credentials !== 'undefined'
  }
})()
