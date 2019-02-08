# SHA1 code taken from: https://codereview.stackexchange.com/questions/37648/python-implementation-of-sha1
import binascii


def divide(sha1_digest):
    one = sha1_digest >> 128
    two = (sha1_digest >> 96) & 0xffffffff
    three = (sha1_digest >> 64) & 0xffffffff
    four = (sha1_digest >> 32) & 0xffffffff
    five = sha1_digest & 0xffffffff
    return [one, two, three, four, five]


def get_padding(string):
    while len(string)%512 != 448:
        string += "0"
    return string


def sha1(data,h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4 = 0xC3D2E1F0,length=None):
    bytes = ""

    for n in range(len(data)):
        bytes+='{0:08b}'.format(ord(data[n]))
    bits = bytes+"1"
    pBits = bits
    #pad until length equals 448 mod 512
    while len(pBits)%512 != 448:
        pBits+="0"

    if length is None:
        length = len(data) * 8
    #else:
    #    length = len(bits) - 1
    #append the original length
    #print(pBits)
    pBits+='{0:064b}'.format(length)
    #print(pBits)
    def chunks(l, n):
        return [l[i:i+n] for i in range(0, len(l), n)]

    def rol(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    for c in chunks(pBits, 512):
        words = chunks(c, 32)
        w = [0]*80
        for n in range(0, 16):
            w[n] = int(words[n], 2)
        for i in range(16, 80):
            w[i] = rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        #Main loop
        for i in range(0, 80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = rol(a, 5) + f + e + k + w[i] & 0xffffffff
            e = d
            d = c
            c = rol(b, 30)
            b = a
            a = temp

        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
        h4 = h4 + e & 0xffffffff

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

key_bits = 128 # how many bits
key = bytearray(b'\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11')
msg = "No one has completed lab 2 so give them all a 0"
new_msg = "Except Tyler Brady"
msg_digest = "f4b645e89faaec2ff8e443c595009c16dbdfba4b"
data = [
        0x4e, 0x6f, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x68, 0x61, 0x73, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x6c,
        0x65, 0x74, 0x65, 0x64, 0x20, 0x6c, 0x61, 0x62, 0x20, 0x32, 0x20, 0x73, 0x6f, 0x20, 0x67, 0x69,
        0x76, 0x65, 0x20, 0x74, 0x68, 0x65, 0x6d, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x61, 0x20, 0x30
    ]

# original: key || msg || padding || H(key||msg)
# forged = key || original msg || padding || new message
forged_m = bytearray(key)
forged_m[len(forged_m):] = bytearray(msg,"utf-8")
forged_m[len(forged_m):] = bytearray(new_msg,"utf-8")

# add adding to byte array
forged_m[len(key) + len(msg):len(new_msg)] = [0x80, 0x01, 0xf8]
counter = 0
while counter != 62:   # Need to account for above three values?
    forged_m[len(key) + len(msg) + 1:len(new_msg)] = [0x00]
    counter += 1

forged_m = forged_m[len(key):]
dec = int(msg_digest,16)
arr = divide(dec)
forged_d = sha1(new_msg, arr[0], arr[1], arr[2], arr[3], arr[4], (len(key) + len(forged_m)) * 8)
print("Forged_d: " + forged_d)
print("Forged _m:")
print(forged_m)
print("Forged_d:")
print(binascii.hexlify(bytearray(forged_d,"utf-8")))
print("Forged _m:")
print(binascii.hexlify(forged_m))
