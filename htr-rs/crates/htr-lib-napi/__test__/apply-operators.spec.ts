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

// String coercion renders the decimal form, which reads the global decimal places. ava runs each
// spec file in its own process, so this file must set them itself.
test.before(() => {
  UnsignedAmount.setDecimalPlaces(2, 18)
})

test('ordering is numeric, not a string comparison of the rendered form', (t) => {
  // The exact failure the browser/wasm gap caused: without the patch, `10 > 9` compares the
  // rendered strings ("0.00000000000000001" vs "0.000000000000000009") and is wrong.
  t.true(UnsignedAmount.fromV2(10n) > UnsignedAmount.fromV2(9n))
  t.true(UnsignedAmount.fromV2(5n) < UnsignedAmount.fromV2(6n))
  t.true(new SignedAmount(10n) > new SignedAmount(9n))
  t.true(new SignedAmount(-1n) < new SignedAmount(2n))
})

test('string coercion uses toString (the decimal form)', (t) => {
  t.is(String(UnsignedAmount.fromV2(5n)), '0.000000000000000005')
  t.is(`${new SignedAmount(-3n)}`, '-0.000000000000000003')
})
