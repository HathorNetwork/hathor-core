// Attaches [Symbol.toPrimitive] to the amount wrappers so the native relational operators
// (<, >, <=, >=) work on UnsignedAmount / SignedAmount — JavaScript cannot declare it from Rust.
//
// Shared by the Node entry (wrapper.js) and the browser/wasm entry (browser-wrapper.mjs) so the
// operators behave identically on both. Without it, a browser/bundler build that loads the
// generated wasm entry directly would fall back to toString() and compare amounts as *strings*
// (e.g. "...normalized: 10" < "...normalized: 9"), silently giving wrong orderings.
//
// For the 'string' hint we defer to toString() (the Rust Debug form). For 'number'/'default' we
// return the underlying value as a bigint so ordering compares with full precision.
// Note: == / === remain reference identity (use .eq()); + / - coerce to bigint (use .add/.sub).
module.exports = function applyOperators(binding) {
  binding.UnsignedAmount.prototype[Symbol.toPrimitive] = function (hint) {
    return hint === 'string' ? this.toString() : this.normalized()
  }
  binding.SignedAmount.prototype[Symbol.toPrimitive] = function (hint) {
    return hint === 'string' ? this.toString() : this.raw()
  }
}
