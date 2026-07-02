// Hand-written browser/wasm entry point (the package.json "browser" field points here). The
// generated browser.js loads the wasm build but, like index.js, cannot declare [Symbol.toPrimitive]
// from Rust. We apply the same shared patch as the Node entry (wrapper.js) so the relational
// operators <, >, <=, >= behave identically in browser/bundler builds; without this, a browser
// build would silently fall back to string comparison of the Debug form.

import * as binding from './browser.js'
import applyOperators from './apply-operators.cjs'

applyOperators(binding)

export * from './browser.js'
