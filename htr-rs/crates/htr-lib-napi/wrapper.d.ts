// Re-export the generated declarations and augment the classes with the
// [Symbol.toPrimitive] member attached at runtime in wrapper.js.
export * from './index.js'

declare module './index.js' {
  interface UnsignedAmount {
    // Returns a string for the 'string' hint (toString), a bigint otherwise (normalized()).
    [Symbol.toPrimitive](hint: string): bigint | string
  }
  interface SignedAmount {
    // Returns a string for the 'string' hint (toString), a bigint otherwise (raw()).
    [Symbol.toPrimitive](hint: string): bigint | string
  }
}
