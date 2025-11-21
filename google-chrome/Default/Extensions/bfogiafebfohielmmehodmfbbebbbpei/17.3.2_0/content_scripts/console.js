// addMessageListener(function (message) {
//   if (message.action === 'event') {
//     switch (message.name) {
//       case 'consoleAutoLogin':           // Logs the vault in using the session storage method.
//         loginConsole(message.data.data.login, message.data.data.password, message.data.data.deviceToken, message.data.data.tokenExpiry, message.data.data.rememberEmail);
//         break;
//     }
//   }
// });

// function loginConsole (login, password, deviceToken, tokenExpiry, rememberEmail) {
//   document.querySelector('.adminLoginBox input[name=email]').value = login;
//   document.querySelector('.adminLoginBox input[name=passwd]').value = password;

//   document.querySelector('.adminLoginBox input[name=remember]').checked = rememberEmail;

//   if (deviceToken) {
//     var tokenData;
//     var old_style_tokens = false;

//     try {
//       tokenData = JSON.parse(window.localStorage.getItem('vault_device_tokens'));
//     } catch (err) {
//       tokenData = {};
//     }

//     // Handle old-style formatting
//     if (tokenData && typeof tokenData.data === 'string') {
//       old_style_tokens = true;
//       tokenData.data = JSON.parse(tokenData.data);
//     }

//     var tokens = (tokenData && tokenData.data && (tokenData.expiry === null || now.getTime() <= tokenData.expiry)) ? tokenData.data : {};

//     if (!tokens[login]) {
//       tokens[login] = deviceToken;

//       if (old_style_tokens) {
//         tokens = JSON.stringify(tokens);
//       }

//       if (tokenExpiry === 0) {
//         window.sessionStorage.setItem('vault_device_tokens', JSON.stringify({
//           expiry: null,
//           data: tokens
//         }));
//       } else {
//         window.localStorage.setItem('vault_device_tokens', JSON.stringify({
//           expiry: null,
//           data: tokens
//         }));
//       }
//     }
//   }

//   document.querySelector('.adminLoginBox .consoleLogin').dispatchEvent(new Event('click'));
// }

// // Triggers autologing in on the console.
// // This is disabled until the Console can logout the Extension, otherwise the user will be trapped in the Console.
// // sendEventMessage('requestConsoleAutoLogin');
