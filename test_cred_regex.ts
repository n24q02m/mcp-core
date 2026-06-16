const unsafe = /[^a-zA-Z0-9.-]/g;

function isUnsafe(str: string) {
  return unsafe.test(str);
}

console.log(isUnsafe("valid"));
console.log(isUnsafe("invalid_"));
console.log(isUnsafe("invalid_"));
