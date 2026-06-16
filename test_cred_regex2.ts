const unsafe = /[^a-zA-Z0-9.-]/g;

function credPath(pluginName: string, sub: string | null) {
  if (!pluginName || unsafe.test(pluginName) || pluginName.includes('..')) {
    throw new Error('Invalid pluginName')
  }
  if (sub !== null && (!sub || unsafe.test(sub) || sub.includes('..'))) {
    throw new Error('Invalid sub')
  }
  return 'ok'
}

console.log(credPath("valid1", "valid_but_fails_due_to_state?"));
