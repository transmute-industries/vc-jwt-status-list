import { Bitstring } from '../src'

it('cannot set negative position', async () => {
  const bs = new Bitstring({ length: 8 })
  const t = () => {
    bs.set(-1, true)
  }
  expect(t).toThrow(TypeError)
})

it('cannot set out of bounds position', async () => {
  const bs = new Bitstring({ length: 8 })
  const t = () => {
    bs.set(8, true)
  }
  expect(t).toThrow(Error)
})

it('can compress', async () => {
  const bs = new Bitstring({ length: 8 })
  bs.set(1, true)
  const compressed = await bs.compressBits()
  expect(compressed).toBeDefined()
})

it('can encode', async () => {
  const bs = new Bitstring({ length: 8 })
  bs.set(1, true)
  const encoded = await bs.encodeBits()
  expect(encoded).toBe('H4sIAAAAAAAAA3MAAB2u3qQBAAAA')
})
