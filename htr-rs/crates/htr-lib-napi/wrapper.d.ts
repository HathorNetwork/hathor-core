// Re-export the generated declarations and augment the classes with the
// [Symbol.toPrimitive] member attached at runtime in wrapper.js.
export * from './index.js'

declare module './index.js' {
  interface TokenAmount {
    [Symbol.toPrimitive](hint: string): bigint
  }
  interface TokenBalance {
    [Symbol.toPrimitive](hint: string): bigint
  }
}
