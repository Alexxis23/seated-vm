M = (1 << 64) - 1

init0 = [0xdbe6d5d5fe4cce2f, 0xa4093822299f31d0, 0x13198a2e03707344, 0x243f6a8885a308d3]
init1 = [0x3bd39e10cb0ef593, 0xc0acf169b5f18a8c, 0xbe5466cf34e90c6c, 0x452821e638d01377]

def le64(b): return int.from_bytes(b, 'little')

data = bytes(range(32))
p = [le64(data[8*j:8*j+8]) for j in range(4)]

v0 = init0[:]
v1 = init1[:]
mul0 = init0[:]
mul1 = init1[:]

for j in range(4):
    v1[j] = (v1[j] + p[j] + mul0[j]) & M
for j in range(4):
    mul0[j] ^= ((v0[j] >> 32) * (v1[j] & 0xffffffff)) & M
for j in range(4):
    v0[j] = (v0[j] + mul1[j]) & M
for j in range(4):
    mul1[j] ^= ((v1[j] >> 32) * (v0[j] & 0xffffffff)) & M

print('pre-zip v0:', [hex(x) for x in v0])
print('pre-zip v1:', [hex(x) for x in v1])

oracle_v0 = [int(x, 16) for x in 'da2e38ab41b95b8e 831aea51162ba746 91f681823ec509fb 51ca10a468002e23'.split()]
oracle_v1 = [int(x, 16) for x in 'ad43d40505171603 4e0a653fd4c6707a e3d50fdbcd3134fe 19a99fb8e98db7ca'.split()]
oracle_mul0 = [int(x, 16) for x in '746aab91354ad145 325aa1742ddf2698 16b90bdaef6bf1c4 3af2d541739ff8c3'.split()]
oracle_mul1 = [int(x, 16) for x in '23e3bace542d2ac7 a5b5ae70457b08c8 8d7a4dfc194696dc 20b8b71392fc0a93'.split()]
print('mul0 match:', mul0 == oracle_mul0, 'mul1 match:', mul1 == oracle_mul1)

d0 = [(oracle_v0[j] - v0[j]) & M for j in range(4)]
d1 = [(oracle_v1[j] - v1[j]) & M for j in range(4)]
print('delta v0:', [hex(x) for x in d0])
print('delta v1:', [hex(x) for x in d1])

# candidate zipper translations
def z_mine(a, b):
    z1 = (((b << 32) & 0x0000FF0000FF0000)
          | (b & 0x0000000000FF0000)
          | ((a >> 8) & 0x00FF00FF00FF00FF)
          | ((b << 56) & M)
          | (((b & 0x0000FF0000FF0000) | (a & 0x00FF00FF00FF00FF)) >> 16)
          | (((b & 0x00000000FF000000) | (a & 0x000000FF00000000)) >> 24)) & M
    z2 = (((b >> 8) & 0x0000FF0000FF0000)
          | ((a >> 16) & 0x00000000FF000000)
          | ((a << 24) & 0x000000FF00000000)
          | (b & 0xFF00000000000000)
          | ((a << 48) & 0x00FF00FF00FF00FF)
          | (a & 0x0000000000FF0000)
          | (((b & 0x000000FF00000000) | (a & 0x00000000FF000000)) >> 24)) & M
    return z1, z2

a, b = v1[1], v1[0]
z1, z2 = z_mine(a, b)
print('mine  z(v1[1],v1[0]): z1=%016x z2=%016x   want d0[1]=%016x d0[0]=%016x' % (z1, z2, d0[1], d0[0]))
z1b, z2b = z_mine(b, a)
print('mine  z(v1[0],v1[1]): z1=%016x z2=%016x   want d0[1]=%016x d0[0]=%016x' % (z1b, z2b, d0[1], d0[0]))
