#!/usr/bin/env python3
"""Put a clean Xenon SMC and a donor Xenon SMC config into a 64MB small-block Xbox 360 NAND image.

The SMC is XENON_CLEAN.bin and the config is Donor Files/smc_config/Xenon.bin, both from
J-Runner-with-Extras and embedded below. The SMC goes where the image's flash header says and the
config goes in its fixed block. Pages keep the image's spare format and get a new ECC. The input is
never modified and the result goes to a new file. The script refuses to run if the image has bad
or remapped blocks in the regions it writes.

Older images such as 1640 keep their SMC after the boot chain and have boot code at 0x1000. Only
the SMC's own pages and the last config block are written on those, because the other config
blocks hold live data.

    py inject_smc.py <target.bin> -o <output.bin> [--smc-only] [--force]
"""

import argparse
import base64
import hashlib
import os
import struct
import sys
import zlib

PAGE_DATA = 512
PAGE_SPARE = 16
PAGE_RAW = PAGE_DATA + PAGE_SPARE
PAGES_PER_BLOCK = 32
# a block's used pages are programmed in 4KB units
PAGES_PER_PROGRAM_UNIT = 8

# where images from 1838 on keep the SMC
STANDARD_SMC_OFFSET = 0x1000
SMC_SIZE = 0x3000
# the four blocks that hold the SMC config on a 64MB small-block image
CONFIG_OFFSET = 0x3DF0000
CONFIG_SIZE = 0x10000
CONFIG_LAST_BLOCK = 0xF7F
CONFIG_LAST_BLOCK_OFFSET = CONFIG_LAST_BLOCK * PAGES_PER_BLOCK * PAGE_DATA
EXPECTED_DATA_SIZE = 0x4000000

SMC_KEY = (0x42, 0x75, 0x4E, 0x79)
# xeBuild's smcKey, used when the target's own SMC doesn't decrypt
DEFAULT_SMC_KEY = bytes((0x8E, 0x03, 0x75, 0xCC))
ERASED_DATA = b"\xFF" * PAGE_DATA
ERASED_SPARE = b"\xFF" * PAGE_SPARE

SMC_MD5 = "6b383b98d920dec5e6d1e3413e6fc654"
CONFIG_MD5 = "6217ca029954071d9ad7f6eeb6a08c39"

# XENON_CLEAN.bin, decrypted, zlib compressed
SMC_BLOB = """
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
Tckdwir/DWR6hiQ=
"""

# Xenon.bin, zlib compressed
CONFIG_BLOB = """
eNrt0y0KAlEUBtA3YBd0V75BRDBodRCTacxjUAzuwGhzGbMCi5sRhKeiaDL7wznpux83XbgpAQAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADA5x3bIbymRhaqKp2vaTUc15u4LfdxV846h3mzF7tFMXGwPxPusvBOa3Sarh8r6dlm
+aCf38JyEfhhPgAAAAAAAAAAAAAAAAAAAL7HBXZSAoY=
"""


class InjectError(Exception):
	pass


def md5(data: bytes) -> str:
	return hashlib.md5(data).hexdigest()


def load_blob(blob: str, expected_md5: str, size: int) -> bytes:
	data = zlib.decompress(base64.b64decode(blob))
	if len(data) != size or md5(data) != expected_md5:
		raise InjectError("embedded data is corrupt")
	return data


def page_ecc(data: bytes, spare: bytes) -> int:
	val = 0
	v = 0
	src = data
	idx = 0
	for bit in range(0x1066):
		if not (bit & 31):
			if bit == 0x1000:
				src = spare
				idx = 0
			(v,) = struct.unpack_from("<I", src, idx)
			v = ~v & 0xFFFFFFFF
			idx += 4
		val ^= v & 1
		v >>= 1
		if val & 1:
			val ^= 0x6954559
		val >>= 1
	return ~val & 0xFFFFFFFF


def page_ecc_ok(raw: bytes, page: int) -> bool:
	off = page * PAGE_RAW
	data = raw[off:off + PAGE_DATA]
	spare = raw[off + PAGE_DATA:off + PAGE_RAW]
	val = page_ecc(data, spare)
	return (
		(spare[12] & 0xC0) == ((val << 6) & 0xC0)
		and spare[13] == (val >> 2) & 0xFF
		and spare[14] == (val >> 10) & 0xFF
		and spare[15] == (val >> 18) & 0xFF
	)


def smc_crypt(data: bytes, encrypt: bool) -> bytes:
	key = list(SMC_KEY)
	out = bytearray()
	for i, c in enumerate(data):
		res = c ^ key[i & 3]
		out.append(res)
		mod = (res if encrypt else c) * 0xFB
		key[(i + 1) & 3] = (key[(i + 1) & 3] + mod) & 0xFF
		key[(i + 2) & 3] = (key[(i + 2) & 3] + (mod >> 8)) & 0xFF
	return bytes(out)


def choose_smc_key(encrypted: bytes) -> bytes:
	"""The SMC's first four bytes. Like xeBuild, keep the image's own if its SMC decrypts."""
	existing = smc_crypt(encrypted, False)
	if existing[-4:] == bytes(4):
		return existing[:4]
	return DEFAULT_SMC_KEY


def user_data(raw: bytes, offset: int, size: int) -> bytes:
	first = offset // PAGE_DATA
	count = size // PAGE_DATA
	return b"".join(raw[p * PAGE_RAW:p * PAGE_RAW + PAGE_DATA] for p in range(first, first + count))


def default_spare(block: int, older_layout: bool) -> bytes:
	"""The spare for a page the target has never programmed, in that layout's format."""
	if older_layout:
		spare = bytearray(b"\xFF" * PAGE_SPARE)
		spare[0] = block & 0xFF
		spare[1] = 0xF0 | (block >> 8)
		spare[12] = 0x3F
		return bytes(spare)
	spare = bytearray(PAGE_SPARE)
	spare[0] = block & 0xFF
	spare[1] = block >> 8
	spare[5] = 0xFF
	return bytes(spare)


def build_page(data: bytes, template: bytes) -> bytes:
	spare = bytearray(template)
	spare[12] &= 0x3F
	val = page_ecc(data, bytes(spare))
	spare[12] |= (val << 6) & 0xC0
	spare[13] = (val >> 2) & 0xFF
	spare[14] = (val >> 10) & 0xFF
	spare[15] = (val >> 18) & 0xFF
	return data + bytes(spare)


def build_region(data: bytes, offset: int, target: bytes, older_layout: bool) -> bytes:
	"""Raw pages for a region. Everything after a block's last used program unit stays erased."""
	first = offset // PAGE_DATA
	count = len(data) // PAGE_DATA
	pages = [data[i * PAGE_DATA:(i + 1) * PAGE_DATA] for i in range(count)]
	last_used = {}
	for i, page in enumerate(pages):
		if page != ERASED_DATA:
			last_used[(first + i) // PAGES_PER_BLOCK] = (first + i) % PAGES_PER_BLOCK
	out = bytearray()
	for i, page in enumerate(pages):
		block, index = divmod(first + i, PAGES_PER_BLOCK)
		if block in last_used and index // PAGES_PER_PROGRAM_UNIT <= last_used[block] // PAGES_PER_PROGRAM_UNIT:
			start = (first + i) * PAGE_RAW + PAGE_DATA
			template = target[start:start + PAGE_SPARE]
			if template == ERASED_SPARE:
				template = default_spare(block, older_layout)
			out += build_page(page, template)
		else:
			out += ERASED_DATA + ERASED_SPARE
	return bytes(out)


def load_image(path: str) -> bytes:
	with open(path, "rb") as f:
		raw = f.read()
	if len(raw) % PAGE_RAW:
		raise InjectError(f"{path}: size {len(raw):#x} is not a whole number of 528 byte pages")
	if len(raw) // PAGE_RAW * PAGE_DATA != EXPECTED_DATA_SIZE:
		raise InjectError(f"{path}: expected a 64MB small-block image with spare, got {len(raw):#x} bytes")
	header = user_data(raw, 0, PAGE_DATA)
	if struct.unpack_from(">H", header, 0)[0] not in (0x0F3F, 0x0F4F, 0xFF3F):
		raise InjectError(f"{path}: unrecognised flash header magic {header[:2].hex()}")
	return raw


def smc_location(raw: bytes, path: str) -> int:
	"""The SMC's offset from the flash header, checked against the image's own contents."""
	header = user_data(raw, 0, PAGE_DATA)
	cb_off = struct.unpack_from(">I", header, 8)[0]
	smc_len, smc_off = struct.unpack_from(">II", header, 0x78)
	if smc_len != SMC_SIZE:
		raise InjectError(f"{path}: the header's SMC size is {smc_len:#x}, the embedded SMC is {SMC_SIZE:#x}")
	if smc_off % PAGE_DATA or smc_off < STANDARD_SMC_OFFSET or smc_off + SMC_SIZE > CONFIG_OFFSET:
		raise InjectError(f"{path}: the header's SMC offset {smc_off:#x} isn't usable")
	if smc_off <= cb_off < smc_off + SMC_SIZE:
		raise InjectError(f"{path}: the header's SMC region overlaps the CB at {cb_off:#x}")
	if smc_crypt(user_data(raw, smc_off, SMC_SIZE), False)[-4:] != bytes(4):
		raise InjectError(f"{path}: there's no valid SMC at the header's offset {smc_off:#x}")
	return smc_off


def check_blocks(raw: bytes, path: str, offset: int, size: int) -> None:
	"""The block's logical id must equal its position, otherwise the region has been remapped."""
	for page in range(offset // PAGE_DATA, (offset + size) // PAGE_DATA):
		spare = raw[page * PAGE_RAW + PAGE_DATA:page * PAGE_RAW + PAGE_RAW]
		if spare[5] != 0xFF:
			raise InjectError(f"{path}: page {page:#x} is marked bad")
		if spare == ERASED_SPARE:
			continue
		lba = spare[0] | ((spare[1] & 0x0F) << 8)
		if lba != page // PAGES_PER_BLOCK:
			raise InjectError(f"{path}: page {page:#x} belongs to logical block {lba:#x}, expected {page // PAGES_PER_BLOCK:#x}")


def verify(output: bytes, target: bytes, regions: list) -> int:
	"""Written regions must match what was built and every other page must equal the target."""
	written = {}
	for offset, built in regions:
		first = offset // PAGE_DATA
		for i in range(len(built) // PAGE_RAW):
			written[first + i] = built[i * PAGE_RAW:(i + 1) * PAGE_RAW]
	changed = 0
	for page in range(len(output) // PAGE_RAW):
		start = page * PAGE_RAW
		page_out = output[start:start + PAGE_RAW]
		if page_out != written.get(page, target[start:start + PAGE_RAW]):
			raise InjectError(f"verification failed at page {page:#x}")
		if page in written and page_out[PAGE_DATA:] != ERASED_SPARE and not page_ecc_ok(output, page):
			raise InjectError(f"page {page:#x} fails its ECC")
		if page_out != target[start:start + PAGE_RAW]:
			changed += 1
	return changed


def main() -> int:
	parser = argparse.ArgumentParser(description="Put a clean Xenon SMC and a donor Xenon SMC config into a 64MB small-block NAND image.")
	parser.add_argument("target", help="image to start from (not modified)")
	parser.add_argument("-o", "--output", required=True, help="new image to write")
	parser.add_argument("--smc-only", action="store_true", help="write the SMC but keep the target's SMC config")
	parser.add_argument("--force", action="store_true", help="overwrite an existing output file")
	args = parser.parse_args()

	output_path = os.path.abspath(args.output)
	if output_path == os.path.abspath(args.target):
		raise InjectError("the output must not be the input image")
	if os.path.exists(output_path) and not args.force:
		raise InjectError(f"{output_path} already exists, use --force to overwrite it")

	target = load_image(args.target)
	smc = load_blob(SMC_BLOB, SMC_MD5, SMC_SIZE)
	config = load_blob(CONFIG_BLOB, CONFIG_MD5, CONFIG_SIZE)

	smc_off = smc_location(target, args.target)
	older_layout = smc_off != STANDARD_SMC_OFFSET
	check_blocks(target, args.target, smc_off, SMC_SIZE)
	smc_key = choose_smc_key(user_data(target, smc_off, SMC_SIZE))
	regions = [(smc_off, build_region(smc_crypt(smc_key + smc[4:], True), smc_off, target, older_layout))]
	if not args.smc_only:
		config_off = CONFIG_LAST_BLOCK_OFFSET if older_layout else CONFIG_OFFSET
		config_data = config[config_off - CONFIG_OFFSET:]
		check_blocks(target, args.target, config_off, len(config_data))
		regions.append((config_off, build_region(config_data, config_off, target, older_layout)))

	output = bytearray(target)
	for offset, built in regions:
		start = offset // PAGE_DATA * PAGE_RAW
		output[start:start + len(built)] = built
	output = bytes(output)
	changed = verify(output, target, regions)

	temp_path = output_path + ".tmp"
	with open(temp_path, "wb") as f:
		f.write(output)
	os.replace(temp_path, output_path)

	smc_old = smc_crypt(user_data(target, smc_off, SMC_SIZE), False)
	smc_new = smc_crypt(user_data(output, smc_off, SMC_SIZE), False)
	print(f"SMC    {md5(smc_old)} -> {md5(smc_new)}  (decrypted, at {smc_off:#x})")
	if args.smc_only:
		print("config kept from target")
	else:
		print(f"config {md5(user_data(target, config_off, len(config_data)))} -> {md5(user_data(output, config_off, len(config_data)))}  (at {config_off:#x})")
	print(f"{changed} pages changed")
	print(f"wrote {output_path} ({md5(output)})")
	return 0


if __name__ == "__main__":
	try:
		sys.exit(main())
	except (InjectError, OSError) as e:
		print(f"error: {e}", file=sys.stderr)
		sys.exit(1)
