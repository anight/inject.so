
import gdb

"""
	limitations:
	- no TLS support
	- only RTLD_NOW
	- no support for __attribute__((constructor)) and __attribute__((destructor))
	- no dependant libraries get loaded
"""

import os, mmap, cffi



class Relocator:

	def __init__(self, el):
		self.el = el

	def relocate(self):
		add_addr = (Elf.DT_HASH, Elf.DT_GNU_HASH, Elf.DT_STRTAB, Elf.DT_SYMTAB,
			Elf.DT_PLTGOT, Elf.DT_JMPREL, Elf.DT_RELA, Elf.DT_VERSYM)
		for no, de in self.el._all_dyn_entries():
			if de.d_tag in add_addr:
				address = self.el.sm.base + self.el.dyn_section.sh_addr + \
					no * self.el.dyn_section.sh_entsize + \
					self.el.ffi.offsetof("Elf64_Dyn", "d_un")
				gdb.execute("set * (long *) %lu = %lu" % (address, de.d_un.d_val + self.el.sm.base))

class SegmentMapper:

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
		self.base = None
		self.mmap_sz = None
		self.segments = []
		self.layout = []

	@staticmethod
	def _flags2prot(v):
		ret = 0
		if 0 != (v & Elf.PF_X):
			ret |= SegmentMapper.PROT_EXEC
		if 0 != (v & Elf.PF_W):
			ret |= SegmentMapper.PROT_WRITE
		if 0 != (v & Elf.PF_R):
			ret |= SegmentMapper.PROT_READ
		return ret

	@staticmethod
	def _up2page(addr):
		return (addr + mmap.PAGESIZE - 1) & -mmap.PAGESIZE

	@staticmethod
	def _down2page(addr):
		return addr & -mmap.PAGESIZE

	@staticmethod
	def _layout_item_unmmapped(s, l):
		return {"type": "unmmapped", "start": s, "length": l, "prot": SegmentMapper.PROT_NONE}

	@staticmethod
	def _layout_item_mmaped(p, s, l):
		return {"type": "mmaped", "start": s, "length": l, "segment": p, "prot": SegmentMapper._flags2prot(p.p_flags)}

	@staticmethod
	def _layout_item_anon(s, l, flags):
		return {"type": "anon", "start": s, "length": l, "prot": SegmentMapper._flags2prot(flags)}

	def add_segment(self, p):
		if (p.p_vaddr & (mmap.PAGESIZE - 1)) != (p.p_offset & (mmap.PAGESIZE - 1)):
			raise Exception("unaligned p_vaddr and p_offset")
		self.segments.append(p)

	def _find_equal_or_greater(self, v):
		ret = None
		for p in self.segments:
			if p.p_vaddr < v:
				continue
			if ret is None or ret.p_vaddr > p.p_vaddr:
				ret = p
		return ret

	def create_layout(self):
		self.mmap_sz = max(map(lambda p: p.p_vaddr + p.p_memsz, self.segments))
		end_addr = SegmentMapper._up2page(self.mmap_sz)
		addr = 0
		while addr < end_addr:
			p = self._find_equal_or_greater(addr)
			assert p is not None
			addr_start = SegmentMapper._down2page(p.p_vaddr)
			addr_end = SegmentMapper._up2page(p.p_vaddr + p.p_memsz)
			addr_f_end = SegmentMapper._up2page(p.p_vaddr + p.p_filesz)

			if addr < addr_start:
				# hole in virtual addresses ? insert some unmmapped memory
				self.layout.append(SegmentMapper._layout_item_unmmapped(addr, addr_start - addr))

			self.layout.append(SegmentMapper._layout_item_mmaped(p, addr_start, addr_f_end - addr_start))

			if addr_f_end < addr_end:
				# the rest is not mapped by file ? this is bss
				self.layout.append(SegmentMapper._layout_item_anon(addr_f_end, addr_end - addr_f_end, p.p_flags))

			addr = addr_end

	@staticmethod
	def _mmap(addr, sz, prot, flags, fd, offset):
		return long(gdb.parse_and_eval("((void *(*)(void *, size_t, int, int, int, long))mmap)(%lu, %lu, %u, %u, %u, %lu)" % (
			addr, sz, prot, flags, fd, offset)))

	@staticmethod
	def _mprotect(addr, sz, prot):
		return int(gdb.parse_and_eval("mprotect(%lu, %lu, %u)" % (addr, sz, prot)))

	def mmap_file(self):
		self.create_layout()
		head = self.layout[0]
		assert head['type'] == 'mmaped'
		assert head['segment'].p_offset == 0
		ret = SegmentMapper._mmap(0, self.mmap_sz, head['prot'], SegmentMapper.MAP_PRIVATE, self.fd, head['segment'].p_offset)
		self.base = long(ret)
		for l in self.layout[1:]:
			addr = self.base + l['start']
			if l['type'] == 'mmaped':
				ret = SegmentMapper._mmap(addr, l['length'], l['prot'],
					SegmentMapper.MAP_PRIVATE | SegmentMapper.MAP_FIXED, self.fd,
					SegmentMapper._down2page(l['segment'].p_offset))
				assert ret == addr
			elif l['type'] == 'unmmapped':
				ret = SegmentMapper._mprotect(addr, l['length'], l['prot'])
				assert ret == 0
			elif l['type'] == 'anon':
				ret = SegmentMapper._mmap(addr, l['length'], l['prot'],
					SegmentMapper.MAP_PRIVATE | SegmentMapper.MAP_FIXED | SegmentMapper.MAP_ANONYMOUS, -1, 0)
				assert ret == addr
			else:
				raise Exception("oops")

	def process_gnu_relro(self, p):
		addr = SegmentMapper._down2page(p.p_vaddr)
		sz = SegmentMapper._up2page(p.p_vaddr + p.p_memsz) - addr
		ret = SegmentMapper._mprotect(self.base + addr, sz, SegmentMapper.PROT_READ)
		assert ret == 0

class ElfLoader:

	def __init__(self, filename):
		fd = os.open(filename, os.O_RDONLY)
		s = os.fstat(fd)
		self.filename = filename
		self.size = s.st_size
		self.mh = mmap.mmap(fd, s.st_size, mmap.MAP_PRIVATE, mmap.PROT_READ)
		os.close(fd)
		self.ffi = cffi.FFI()
		self.ffi.cdef(Elf.cdefs)
		self.elf_hdr = self._read("Elf64_Ehdr", 0)
		sh_str = self._read("Elf64_Shdr", self.elf_hdr.e_shoff + self.elf_hdr.e_shstrndx * self.ffi.sizeof("Elf64_Shdr"))
		self.strtab = sh_str.sh_offset
		self.dyn_section = None

	def _strz(self, offset):
		ret = ''
		self.mh.seek(self.strtab + offset)
		while True:
			ch = self.mh.read(1)
			if ch == "\0":
				return ret
			ret += ch

	def _read(self, type, offset):
		sz = self.ffi.sizeof(type)
		self.mh.seek(offset)
		assert offset + sz <= self.size
		b = self.mh.read(sz)
		ret = self.ffi.new(type + "*")
		(self.ffi.buffer(ret))[:] = b
		return ret

	def _all_phdrs(self):
		for ph in range(self.elf_hdr.e_phnum):
			phdr = self._read("Elf64_Phdr", self.elf_hdr.e_phoff + ph * self.ffi.sizeof("Elf64_Phdr"))
			yield phdr

	def _all_shdrs(self):
		for sh in range(self.elf_hdr.e_shnum):
			shdr = self._read("Elf64_Shdr", self.elf_hdr.e_shoff + sh * self.ffi.sizeof("Elf64_Shdr"))
			yield shdr

	def _all_dyn_entries(self):
		for de in range(self.dyn_section.sh_size / self.dyn_section.sh_entsize):
			dyn = self._read("Elf64_Dyn", self.dyn_section.sh_offset + de * self.ffi.sizeof("Elf64_Dyn"))
			if dyn.d_tag == 0:
				break
			yield de, dyn

	def injectso(self):
		i_fd = int(gdb.parse_and_eval("open(\"%s\", 0)" % self.filename))
		assert i_fd >= 0
		self.sm = SegmentMapper(i_fd)
		gnu_relro = None

		for phdr in self._all_phdrs():
			if phdr.p_type == Elf.PT_LOAD:
				self.sm.add_segment(phdr)
			elif phdr.p_type == Elf.PT_GNU_RELRO:
				gnu_relro = phdr
			elif phdr.p_type == Elf.PT_TLS:
				raise Exception("TLS not supported")

		self.sm.mmap_file()

		self.r = Relocator(self)

		for shdr in self._all_shdrs():
			if shdr.sh_type == Elf.SHT_DYNAMIC:
				self.dyn_section = shdr

		self.r.relocate()

		if gnu_relro is not None:
			self.sm.process_gnu_relro(gnu_relro)

		# process symbol resolution

		assert 0 == int(gdb.parse_and_eval("close(%d)" % i_fd))

	def mmap_sz(self):
		self.sm = SegmentMapper(-1)
		for phdr in self._all_phdrs():
			if phdr.p_type == Elf.PT_LOAD:
				self.sm.add_segment(phdr)
		self.sm.create_layout()
		return self.sm._up2page(self.sm.mmap_sz)

class injectso(gdb.Command):
	def __init__(self):
		super(injectso, self).__init__("injectso", gdb.COMMAND_USER)

	def invoke(self, filename, from_tty):
		el = ElfLoader(filename).injectso()

injectso()

class dumpso(gdb.Command):
	def __init__(self):
		super(dumpso, self).__init__("dumpso", gdb.COMMAND_USER)

	def invoke(self, args, from_tty):
		soname, outname = args.split()
		el = ElfLoader(soname)
		mmap_sz = el.mmap_sz()
		i_proc = gdb.execute('i proc', to_string=True)
		pid = int(i_proc.split("\n")[0].split()[1])
		base = None

		sections = [ sh for sh in el._all_shdrs() ]

		def dump(out, addr, sz, data):
			def dump_line(addr, data):
				a = 0
				for s in sections:
					if s.sh_addr > 0:
						if base + s.sh_addr >= addr and base + s.sh_addr < addr + 16:
							out.write(" > %x: %s\n" % (base + s.sh_addr, el._strz(s.sh_name)))
				out.write("%x " % addr)
				for i1 in range(4):
					for i2 in range(4):
						out.write("%c%02x" % ((' ', '|')[i2 == 0], ord(data[a])))
						a += 1
				out.write("\n")
			while sz > 0:
				dump_line(addr, data)
				addr += 16
				sz -= 16
				data = data[16:]

		with open(outname, 'w+') as out:
			with open('/proc/%u/maps' % pid) as maps:
				with open('/proc/%u/mem' % pid) as mem:
					for line in maps.xreadlines():
						line = line.rstrip()
						if base is None and line.endswith('/' + soname):
							base = int(line.split()[0].split('-')[0], 16)
						if base is not None:
							ar, p = line.split(' ', 2)[:2]
							af, at = ar.split('-')
							af = int(af, 16)
							at = int(at, 16)
							if af >= base and at <= base + mmap_sz and p != '---p':
								print "dumping", ar, p
								os.lseek(mem.fileno(), af, os.SEEK_SET)
								data = os.read(mem.fileno(), at - af)
								dump(out, af, at - af, data)
dumpso()

class Elf:

	# from elf.h
	PF_X           = (1 << 0) # Segment is executable
	PF_W           = (1 << 1) # Segment is writable
	PF_R           = (1 << 2) # Segment is readable

	PT_LOAD        = 1 # Loadable program segment
	PT_DYNAMIC     = 2 # Dynamic linking information
	PT_TLS         = 7 # Thread-local storage segment
	PT_GNU_RELRO   = 0x6474e552 # Read-only after relocation

	SHT_DYNAMIC    = 6 # Dynamic linking information

	DT_PLTGOT      = 3 # Processor defined value
	DT_HASH        = 4 # Address of symbol hash table
	DT_STRTAB      = 5 # Address of string table
	DT_SYMTAB      = 6 # Address of symbol table
	DT_RELA        = 7 # Address of Rela relocs
	DT_REL         = 17 # Address of Rel relocs
	DT_JMPREL      = 23 # Address of PLT relocs
	DT_GNU_HASH    = 0x6ffffef5 # GNU-style hash table.
	DT_VERSYM      = 0x6ffffff0 # some stuff

	cdefs = """
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

		typedef struct
		{
		  Elf64_Word	sh_name;		/* Section name (string tbl index) */
		  Elf64_Word	sh_type;		/* Section type */
		  Elf64_Xword	sh_flags;		/* Section flags */
		  Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
		  Elf64_Off	sh_offset;		/* Section file offset */
		  Elf64_Xword	sh_size;		/* Section size in bytes */
		  Elf64_Word	sh_link;		/* Link to another section */
		  Elf64_Word	sh_info;		/* Additional section information */
		  Elf64_Xword	sh_addralign;		/* Section alignment */
		  Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
		} Elf64_Shdr;

		typedef struct
		{
		  Elf64_Sxword	d_tag;			/* Dynamic entry type */
		  union
		    {
		      Elf64_Xword d_val;		/* Integer value */
		      Elf64_Addr d_ptr;			/* Address value */
		    } d_un;
		} Elf64_Dyn;
	"""

