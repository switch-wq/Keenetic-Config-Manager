import struct, sys
from pathlib import Path

def align4(b: bytearray):
    while len(b)%4: b += b'\x00'

def ordinal(n):
    return struct.pack('<HH',0xFFFF,n)

def res_entry(data, typ, name, lang=0, memflags=0x1030):
    h=bytearray()
    h += ordinal(typ) if isinstance(typ,int) else typ.encode('utf-16le')+b'\x00\x00'
    h += ordinal(name) if isinstance(name,int) else name.encode('utf-16le')+b'\x00\x00'
    while (8+len(h))%4: h += b'\x00'
    h += struct.pack('<IHHII',0,memflags,lang,0,0)
    header_size=8+len(h)
    out=bytearray(struct.pack('<II',len(data),header_size))
    out += h
    out += data
    align4(out)
    return out

def make_res(ico_path,res_path):
    ico=Path(ico_path).read_bytes()
    reserved,itype,count=struct.unpack_from('<HHH',ico,0)
    assert reserved==0 and itype==1
    entries=[]
    off=6
    for i in range(count):
        w,h,cc,rsv,planes,bpp,size,offset=struct.unpack_from('<BBBBHHII',ico,off)
        off += 16
        img=ico[offset:offset+size]
        entries.append((w,h,cc,rsv,planes,bpp,size,img))
    out=bytearray()
    out += struct.pack('<IIHHHHIHHII',0,32,0xFFFF,0,0xFFFF,0,0,0,0,0,0)
    for idx,e in enumerate(entries,1):
        out += res_entry(e[7],3,idx)
    grp=bytearray(struct.pack('<HHH',0,1,count))
    for idx,e in enumerate(entries,1):
        w,h,cc,rsv,planes,bpp,size,_=e
        grp += struct.pack('<BBBBHHIH',w,h,cc,rsv,planes,bpp,size,idx)
    out += res_entry(bytes(grp),14,1)
    Path(res_path).write_bytes(out)
    print(f'wrote {res_path}: {len(out)} bytes, {count} images')

if __name__=='__main__':
    make_res(sys.argv[1],sys.argv[2])
