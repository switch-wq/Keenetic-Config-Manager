from pathlib import Path
import struct, sys

exe = Path(sys.argv[1]).read_bytes()
out_ico = Path(sys.argv[2])
out_png = Path(sys.argv[3])

png_sig = b'\x89PNG\r\n\x1a\n'
png_start = exe.find(png_sig)
if png_start < 0:
    raise SystemExit('embedded PNG not found')

pos = png_start + 8
while True:
    if pos + 12 > len(exe):
        raise SystemExit('truncated embedded PNG')
    ln = struct.unpack('>I', exe[pos:pos+4])[0]
    typ = exe[pos+4:pos+8]
    pos += 12 + ln
    if typ == b'IEND':
        png_end = pos
        break
png = exe[png_start:png_end]

def parse_ico_at(start):
    if start < 0 or start + 6 > len(exe):
        return None
    reserved, typ, count = struct.unpack_from('<HHH', exe, start)
    if reserved != 0 or typ != 1 or not (1 <= count <= 64):
        return None
    table_end = start + 6 + count * 16
    if table_end > len(exe):
        return None
    max_end = 0
    for i in range(count):
        off = start + 6 + i*16
        size, rel = struct.unpack_from('<II', exe, off + 8)
        if size <= 0 or rel < 6 + count*16:
            return None
        max_end = max(max_end, rel + size)
    end = start + max_end
    if end > len(exe):
        return None
    return exe[start:end]

ico = None
sig = b'\x00\x00\x01\x00'
search = png_end
while True:
    p = exe.find(sig, search)
    if p < 0:
        break
    ico = parse_ico_at(p)
    if ico is not None:
        break
    search = p + 1

if ico is None:
    search = 0
    while True:
        p = exe.find(sig, search, png_start)
        if p < 0:
            break
        ico = parse_ico_at(p)
        if ico is not None:
            break
        search = p + 1

if ico is None:
    raise SystemExit('embedded ICO not found')

out_ico.parent.mkdir(parents=True, exist_ok=True)
out_png.parent.mkdir(parents=True, exist_ok=True)
out_ico.write_bytes(ico)
out_png.write_bytes(png)
print(f'ICO: {len(ico)} bytes -> {out_ico}')
print(f'PNG: {len(png)} bytes -> {out_png}')
