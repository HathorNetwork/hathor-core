// Type declaration for the shared operator patch (apply-operators.cjs), so the entry wrappers and
// tests that import it type-check. `binding` carries the two generated classes whose prototypes get
// the [Symbol.toPrimitive] member attached.
declare function applyOperators(binding: {
  UnsignedAmount: Function
  SignedAmount: Function
}): void

export = applyOperators
