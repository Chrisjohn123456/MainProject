// Log when the extension is installed or updated
chrome.runtime.onInstalled.addListener(() => {
    console.log('Phishing Detection Tool installed.');
  });