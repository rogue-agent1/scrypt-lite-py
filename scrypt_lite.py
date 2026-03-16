import hashlib,struct
def pbkdf2_sha256(pw,salt,c=1,dklen=32):
    if isinstance(pw,str): pw=pw.encode()
    if isinstance(salt,str): salt=salt.encode()
    import hmac
    u=hmac.new(pw,salt+struct.pack('>I',1),'sha256').digest()
    result=bytearray(u)
    for _ in range(c-1):
        u=hmac.new(pw,u,'sha256').digest()
        for j in range(len(result)): result[j]^=u[j]
    return bytes(result[:dklen])
def salsa20_8(B):
    x=list(struct.unpack('<16I',B))
    z=list(x)
    def R(a,b,n): return ((a+b)&0xFFFFFFFF)
    for _ in range(4):
        for a,b,c,d in [(4,0,12,7),(8,4,0,9),(12,8,4,13),(0,12,8,18),
                         (9,5,1,7),(13,9,5,9),(1,13,9,13),(5,1,13,18),
                         (14,10,6,7),(2,14,10,9),(6,2,14,13),(10,6,2,18),
                         (3,15,11,7),(7,3,15,9),(11,7,3,13),(15,11,7,18)]:
            t=(z[b]+z[c])&0xFFFFFFFF
            z[a]^=((t<<d)|(t>>(32-d)))&0xFFFFFFFF
    return struct.pack('<16I',*((x[i]+z[i])&0xFFFFFFFF for i in range(16)))
def scrypt(pw,salt,N=1024,r=1,p=1,dklen=32):
    B=pbkdf2_sha256(pw,salt,1,128*r*p)
    for i in range(p):
        block=bytearray(B[i*128*r:(i+1)*128*r])
        V=[]
        for _ in range(N):
            V.append(bytes(block))
            block=bytearray(salsa20_8(bytes(block[:64]))+salsa20_8(bytes(block[64:128])) if len(block)>=128 else salsa20_8(bytes(block[:64])))
            if len(block)<128: block.extend(b'\x00'*(128-len(block)))
        for _ in range(N):
            j=int.from_bytes(block[:8],'little')%N
            vb=V[j]
            for k in range(min(len(block),len(vb))): block[k]^=vb[k]
            block=bytearray(salsa20_8(bytes(block[:64]))+salsa20_8(bytes(block[64:128])))
            if len(block)<128: block.extend(b'\x00'*(128-len(block)))
    return hashlib.sha256(bytes(block)).hexdigest()[:dklen*2]
if __name__=="__main__":
    h1=scrypt("password","salt",N=64)
    h2=scrypt("password","salt",N=64)
    h3=scrypt("password","other",N=64)
    assert h1==h2 and h1!=h3
    print(f"scrypt: {h1[:32]}...")
    print("All tests passed!")
