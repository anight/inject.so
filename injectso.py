
import gdb

"""
	limitations:
	- no threads support
	- no TLS support
"""

import os, mmap, cffi

class SegmentLoader:

	# from elf.h
	PF_X           = (1 << 0) # Segment is executable
	PF_W           = (1 << 1) # Segment is writable
	PF_R           = (1 << 2) # Segment is readable

	PT_LOAD        = 1 # Loadable program segment
	PT_DYNAMIC     = 2 # Dynamic linking information
	PT_GNU_RELRO   = 0x6474e552 # Read-only after relocation

	# from mman.h
	PROT_READ      = 0x1 # page can be read
	PROT_WRITE     = 0x2 # page can be written
	PROT_EXEC      = 0x4 # page can be executed
	PROT_NONE      = 0x0 # page can not be accessed

	MAP_SHARED     = 0x01 # Share changes
	MAP_PRIVATE    = 0x02 # Changes are private
	MAP_FIXED      = 0x10 # Interpret addr exactly
	MAP_ANONYMOUS  = 0x20 # don't use a file

	def __init__(self, fd):
		self.fd = fd
		self.base = 0
		self.mmap_sz = None
		self.segments = []
		self.layout = []

	@staticmethod
	def flags2prot(v):
		ret = 0
		if 0 != (v & SegmentLoader.PF_X):
			ret |= SegmentLoader.PROT_EXEC
		if 0 != (v & SegmentLoader.PF_W):
			ret |= SegmentLoader.PROT_WRITE
		if 0 != (v & SegmentLoader.PF_R):
			ret |= SegmentLoader.PROT_READ
		return ret

	@staticmethod
	def up2page(addr):
		return ((addr + mmap.PAGESIZE - 1) & -mmap.PAGESIZE) / mmap.PAGESIZE

	@staticmethod
	def down2page(addr):
		return (addr & -mmap.PAGESIZE) / mmap.PAGESIZE

	@staticmethod
	def layout_item_unmapped(s, l):
		return {"type": "unmapped", "start": s * mmap.PAGESIZE, "length": l * mmap.PAGESIZE, "prot": SegmentLoader.PROT_NONE}

	@staticmethod
	def layout_item_mmaped(p, s, l):
		return {"type": "mmaped", "start": s * mmap.PAGESIZE, "length": l * mmap.PAGESIZE, "segment": p, "prot": SegmentLoader.flags2prot(p.p_flags)}

	@staticmethod
	def layout_item_anon(s, l, flags):
		return {"type": "anon", "start": s * mmap.PAGESIZE, "length": l * mmap.PAGESIZE, "prot": SegmentLoader.flags2prot(flags)}

	def load(self, p):
		if (p.p_vaddr & (mmap.PAGESIZE - 1)) != (p.p_offset & (mmap.PAGESIZE - 1)):
			raise Exception("unaligned p_vaddr and p_offset")
		# xxx: check if they sorted by vaddr
		self.segments.append(p)

	def find_equal_or_greater(self, v):
		ret = None
		for p in self.segments:
			if p.p_vaddr < v:
				continue
			if ret is None or ret.p_vaddr > p.p_vaddr:
				ret = p
		return ret

	def create_layout(self):
		self.mmap_sz = max(map(lambda p: p.p_vaddr + p.p_memsz, self.segments))
		end_page = SegmentLoader.up2page(self.mmap_sz)
		page = 0
		while page < end_page:
			p = self.find_equal_or_greater(page * mmap.PAGESIZE)
			p_start = SegmentLoader.down2page(p.p_vaddr)
			p_end = SegmentLoader.up2page(p.p_vaddr + p.p_memsz)
			p_f_end = SegmentLoader.up2page(p.p_vaddr + p.p_filesz)

			if page < p_start:
				# hole in virtual addresses ? insert some unmapped memory
				self.layout.append(SegmentLoader.layout_item_unmapped(page, p_start - page))

			self.layout.append(SegmentLoader.layout_item_mmaped(p, p_start, p_f_end - p_start))

			if p_f_end < p_end:
				# the rest is not mapped by file ? this is bss
				self.layout.append(SegmentLoader.layout_item_anon(p_f_end, p_end - p_f_end, p.p_flags))

			page = p_end

		print self.layout

	@staticmethod
	def mmap(addr, sz, prot, flags, fd, offset):
		return long(gdb.parse_and_eval("$mmap()(%lu, %lu, %u, %u, %u, %lu)" % (
			addr, sz, prot, flags, fd, offset)))

	@staticmethod
	def mprotect(addr, sz, prot):
		return int(gdb.parse_and_eval("mprotect(%lu, %lu, %u)" % (addr, sz, prot)))

	def map(self):
		self.create_layout()
		head = self.layout[0]
		assert head['type'] == 'mmaped'
		assert head['segment'].p_offset == 0
		ret = SegmentLoader.mmap(0, self.mmap_sz, head['prot'], SegmentLoader.MAP_PRIVATE, self.fd, head['segment'].p_offset)
		self.base = long(ret)
		for l in self.layout[1:]:
			addr = self.base + l['start']
			if l['type'] == 'mmaped':
				ret = SegmentLoader.mmap(addr, l['length'], l['prot'],
					SegmentLoader.MAP_PRIVATE | SegmentLoader.MAP_FIXED, self.fd,
					mmap.PAGESIZE * SegmentLoader.down2page(l['segment'].p_offset))
				assert ret == addr
			elif l['type'] == 'unmapped':
				ret = SegmentLoader.mprotect(addr, l['length'], l['prot'])
				assert ret == 0
			elif l['type'] == 'anon':
				ret = SegmentLoader.mmap(addr, l['length'], l['prot'],
					SegmentLoader.MAP_PRIVATE | SegmentLoader.MAP_FIXED | SegmentLoader.MAP_ANONYMOUS, -1, 0)
				assert ret == addr
			else:
				raise Exception("oops")

	def process_gnu_relro(self, p):
		addr = SegmentLoader.down2page(p.p_vaddr) * mmap.PAGESIZE
		sz = SegmentLoader.up2page(p.p_vaddr + p.p_memsz) * mmap.PAGESIZE - addr
		ret = SegmentLoader.mprotect(self.base + addr, sz, SegmentLoader.PROT_READ)
		assert ret == 0

class ElfLoader:

	def __init__(self, mh, i_fd, size):
		self.mh = mh
		self.sl = SegmentLoader(i_fd)
		self.ffi = cffi.FFI()
		self.ffi.cdef(elf_cdefs)
		self.size = size

	def read(self, type, offset):
		sz = self.ffi.sizeof(type)
		self.mh.seek(offset)
		b = self.mh.read(sz)
		ret = self.ffi.new(type + "*")
		(self.ffi.buffer(ret))[:] = b
		return ret

	def load_so(self):
		gnu_relro = None

		elf_hdr = self.read("Elf64_Ehdr", 0)

		for ph in range(elf_hdr.e_phnum):
			phdr = self.read("Elf64_Phdr", elf_hdr.e_phoff + ph * self.ffi.sizeof("Elf64_Phdr"))
			if phdr.p_type == SegmentLoader.PT_LOAD:
				self.sl.load(phdr)
			elif phdr.p_type == SegmentLoader.PT_GNU_RELRO:
				gnu_relro = phdr

		self.sl.map()

		# process relocations 

		if gnu_relro is not None:
			self.sl.process_gnu_relro(gnu_relro)

class injectso(gdb.Function):
	def __init__(self):
		super(injectso, self).__init__("injectso")

	def invoke(self, filename):
		fd = os.open(filename.string(), os.O_RDONLY)
		s = os.fstat(fd)
		i_fd = gdb.parse_and_eval("open(\"%s\", 0)" % filename.string())
		assert i_fd >= 0
		mh = mmap.mmap(fd, s.st_size, mmap.MAP_PRIVATE, mmap.PROT_READ)
		os.close(fd)
		ElfLoader(mh, i_fd, s.st_size).load_so()
		assert 0 == gdb.parse_and_eval("close(%d)" % i_fd)
		mh.close()
		return 0

injectso()

class gdbmmap(gdb.Function):
	def __init__(self):
		super(gdbmmap, self).__init__("mmap")

	def invoke(self):
		return gdb.parse_and_eval("(void *(*)(void *, size_t, int, int, int, long))mmap")

gdbmmap()

elf_cdefs = """
		/* Type for a 16-bit quantity.  */
		typedef uint16_t Elf64_Half;

		/* Types for signed and unsigned 32-bit quantities.  */
		typedef uint32_t Elf64_Word;
		typedef	int32_t  Elf64_Sword;

		/* Types for signed and unsigned 64-bit quantities.  */
		typedef uint64_t Elf64_Xword;
		typedef	int64_t  Elf64_Sxword;

		/* Type of addresses.  */
		typedef uint64_t Elf64_Addr;

		/* Type of file offsets.  */
		typedef uint64_t Elf64_Off;

		/* Type for section indices, which are 16-bit quantities.  */
		typedef uint16_t Elf64_Section;

		/* Type for version symbol information.  */
		typedef Elf64_Half Elf64_Versym;

		typedef struct
		{
		  unsigned char	e_ident[16];	/* Magic number and other info */
		  Elf64_Half	e_type;			/* Object file type */
		  Elf64_Half	e_machine;		/* Architecture */
		  Elf64_Word	e_version;		/* Object file version */
		  Elf64_Addr	e_entry;		/* Entry point virtual address */
		  Elf64_Off	e_phoff;		/* Program header table file offset */
		  Elf64_Off	e_shoff;		/* Section header table file offset */
		  Elf64_Word	e_flags;		/* Processor-specific flags */
		  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
		  Elf64_Half	e_phentsize;		/* Program header table entry size */
		  Elf64_Half	e_phnum;		/* Program header table entry count */
		  Elf64_Half	e_shentsize;		/* Section header table entry size */
		  Elf64_Half	e_shnum;		/* Section header table entry count */
		  Elf64_Half	e_shstrndx;		/* Section header string table index */
		} Elf64_Ehdr;

		typedef struct
		{
		  Elf64_Word	p_type;			/* Segment type */
		  Elf64_Word	p_flags;		/* Segment flags */
		  Elf64_Off	p_offset;		/* Segment file offset */
		  Elf64_Addr	p_vaddr;		/* Segment virtual address */
		  Elf64_Addr	p_paddr;		/* Segment physical address */
		  Elf64_Xword	p_filesz;		/* Segment size in file */
		  Elf64_Xword	p_memsz;		/* Segment size in memory */
		  Elf64_Xword	p_align;		/* Segment alignment */
		} Elf64_Phdr;
	"""

