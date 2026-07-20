// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

import test from 'ava'
import applyOperators from '../apply-operators.cjs'
import { UnsignedAmount, SignedAmount } from '../index.js'

// apply-operators.cjs is the shared [Symbol.toPrimitive] patch applied by BOTH the Node entry
// (wrapper.js) and the browser/wasm entry (browser-wrapper.mjs). The wasm target can't be built
// here, so this exercises the shared logic directly against the native binding — the browser entry
// wires the identical call, so this is what guards the browser ordering operators from regressing.
// (These classes are the raw, unpatched ones from index.js, since wrapper.js is not imported here.)
applyOperators({ UnsignedAmount, SignedAmount })

test('ordering is numeric, not a string comparison of the Debug form', (t) => {
  // The exact failure the browser/wasm gap caused: without the patch, `10 > 9` compares the Debug
  // strings ("...normalized: 10" vs "...normalized: 9") and is wrong.
  t.true(UnsignedAmount.fromV2(10n) > UnsignedAmount.fromV2(9n))
  t.true(UnsignedAmount.fromV2(5n) < UnsignedAmount.fromV2(6n))
  t.true(new SignedAmount(10n) > new SignedAmount(9n))
  t.true(new SignedAmount(-1n) < new SignedAmount(2n))
})

test('string coercion uses toString (the Rust Debug form)', (t) => {
  t.is(String(UnsignedAmount.fromV2(5n)), 'V2 { normalized: 5 }')
  t.is(`${new SignedAmount(-3n)}`, 'SignedAmount(-3)')
})
