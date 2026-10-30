#!/usr/bin/env python3
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
"""Crops a PNG screenshot: pngcrop.py IN OUT X Y W H.

Pure Python, so the device scripts need nothing beyond the standard library. Handles what
`screencap -p` writes: 8-bit RGB or RGBA, not interlaced.
"""
import struct
import sys
import zlib


def read_png(path, max_rows=None):
    """Decodes [path]; with [max_rows], only that many rows from the top (filters only look up)."""
    data = open(path, 'rb').read()
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError(f'{path}: not a PNG')
    pos, idat, header = 8, b'', None
    while pos < len(data):
        length, kind = struct.unpack('>I4s', data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if kind == b'IHDR':
            header = struct.unpack('>IIBBBBB', body)
        elif kind == b'IDAT':
            idat += body
        elif kind == b'IEND':
            break
    width, height, depth, color, _, _, interlace = header
    if depth != 8 or color not in (2, 6) or interlace:
        raise ValueError(f'{path}: unsupported PNG (depth {depth}, colour {color})')
    bpp = 4 if color == 6 else 3
    stride = width * bpp
    count = height if max_rows is None else min(height, max_rows)
    raw = zlib.decompressobj().decompress(idat, (stride + 1) * count)
    rows, prev, i = [], bytearray(stride), 0
    for _ in range(count):
        kind, line = raw[i], bytearray(raw[i + 1:i + 1 + stride])
        i += 1 + stride
        for x in range(stride):
            left = line[x - bpp] if x >= bpp else 0
            up = prev[x]
            if kind == 1:
                line[x] = (line[x] + left) & 0xff
            elif kind == 2:
                line[x] = (line[x] + up) & 0xff
            elif kind == 3:
                line[x] = (line[x] + ((left + up) >> 1)) & 0xff
            elif kind == 4:
                corner = prev[x - bpp] if x >= bpp else 0
                p = left + up - corner
                pa, pb, pc = abs(p - left), abs(p - up), abs(p - corner)
                pred = left if pa <= pb and pa <= pc else up if pb <= pc else corner
                line[x] = (line[x] + pred) & 0xff
        rows.append(line)
        prev = line
    return width, height, color, bpp, rows


def write_png(path, width, height, color, rows):
    def chunk(kind, body):
        return (struct.pack('>I', len(body)) + kind + body +
                struct.pack('>I', zlib.crc32(kind + body) & 0xffffffff))
    raw = b''.join(b'\x00' + bytes(r) for r in rows)
    with open(path, 'wb') as out:
        out.write(b'\x89PNG\r\n\x1a\n')
        out.write(chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, color, 0, 0, 0)))
        out.write(chunk(b'IDAT', zlib.compress(raw, 9)))
        out.write(chunk(b'IEND', b''))


def main():
    src, dst, x, y, w, h = sys.argv[1], sys.argv[2], *map(int, sys.argv[3:7])
    width, height, color, bpp, rows = read_png(src, max_rows=y + h)
    w, h = min(w, width - x), min(h, height - y)
    cropped = [r[x * bpp:(x + w) * bpp] for r in rows[y:y + h]]
    write_png(dst, w, h, color, cropped)


if __name__ == '__main__':
    main()
