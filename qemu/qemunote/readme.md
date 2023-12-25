# QEMU ESCAPE 
# COMMUNICATE VIA MMIO 
# DIRECT MEMORY ACCESS

```C
#include "qemu/osdep.h"
#include "hw/pci/pci_device.h"
#include "hw/qdev-properties.h"
#include "qemu/module.h"
#include "sysemu/kvm.h"
#include "qom/object.h"
#include "qapi/error.h"

#include "hw/char/note_service.h"
#include "qemu/queue.h"

#define PAGE_SIZE 0x1000

typedef struct NoteEntry {
	uint64_t id;
	uint64_t size;
	uint8_t * content;
	QTAILQ_ENTRY(NoteEntry) next;
} NoteEntry;

typedef struct NoteCmdHdr {
	uint32_t cmd_type;
	uint32_t res;
	uint32_t note_id;
	uint32_t note_size;
	uint32_t encrypt_offset;
	uint32_t new_note_id;
	uint64_t note_addr;
} NoteCmdHdr;

typedef struct PCINoteDevState {
	PCIDevice parent_obj;

	MemoryRegion mmio;

	uint32_t reg[0x20];
	QTAILQ_HEAD(, NoteEntry) notes;
} PCINoteDevState;

OBJECT_DECLARE_SIMPLE_TYPE(PCINoteDevState, PCI_NOTE_DEV)

static inline dma_addr_t note_addr64(uint32_t low, uint32_t high)
{
    if (sizeof(dma_addr_t) == 4) {
        return low;
    } else {
        return low | (((dma_addr_t)high << 16) << 16);
    }
}


static uint64_t pci_notedev_mmio_read(void *opaque, hwaddr addr, unsigned size);
static void pci_notedev_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size);
static void pci_notedev_reset(PCINoteDevState *ms);
static void do_command(PCINoteDevState *ms);


static const MemoryRegionOps pci_notedev_mmio_ops = {
	.read       = pci_notedev_mmio_read,
	.write      = pci_notedev_mmio_write,
	.endianness = DEVICE_LITTLE_ENDIAN,
	.impl = {
		.min_access_size = 1,
		.max_access_size = 4,
	},
};

static void pci_notedev_realize(PCIDevice *pci_dev, Error **errp) {
	PCINoteDevState *s = PCI_NOTE_DEV(pci_dev);

	memory_region_init_io(&s->mmio, OBJECT(s), &pci_notedev_mmio_ops, s, "note-service-mmio", 0x100);
	pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);
	s->mmio.disable_reentrancy_guard = true;

	bzero(&s->reg, sizeof(s->reg));
	QTAILQ_INIT(&s->notes);
}

static void pci_notedev_uninit(PCIDevice *pci_dev) {
	PCINoteDevState *ms = PCI_NOTE_DEV(pci_dev);

	pci_notedev_reset(ms);
}

static void notedev_reset(DeviceState *s) {
	PCINoteDevState *ms = PCI_NOTE_DEV(s);

	pci_notedev_reset(ms);
}

static void pci_notedev_reset(PCINoteDevState *ms) {
	NoteEntry *note;
	bzero(&ms->reg, sizeof(ms->reg));
	for (;;) {
        note = QTAILQ_FIRST(&ms->notes);
        if (note == NULL) {
            break;
        }
		QTAILQ_REMOVE(&ms->notes, note, next);

		if (note->content) {
			g_free(note->content);
		}
		g_free(note);
    }
}

static void pci_notedev_class_init(ObjectClass *klass, void *data) {
	DeviceClass *dc = DEVICE_CLASS(klass);
	PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

	k->realize = pci_notedev_realize;
	k->exit = pci_notedev_uninit;
	k->vendor_id = NOTE_PCI_VENDOR_ID;
	k->device_id = NOTE_PCI_DEVICE_ID;
	k->revision = 0x00;
	k->class_id = PCI_CLASS_OTHERS;
	dc->desc = "ISITDTU CTF 2023 Challenge : Note service as a QEMU device";
	set_bit(DEVICE_CATEGORY_MISC, dc->categories);
	dc->reset = notedev_reset;
}

static const TypeInfo pci_notedev_info = {
	.name          = TYPE_PCI_NOTE_DEV,
	.parent        = TYPE_PCI_DEVICE,
	.instance_size = sizeof(PCINoteDevState),
	.class_init    = pci_notedev_class_init,
	.interfaces = (InterfaceInfo[]) {
		{ INTERFACE_CONVENTIONAL_PCI_DEVICE },
		{ },
	},
};

static void pci_notedev_register_types(void) {
	type_register_static(&pci_notedev_info);
}

type_init(pci_notedev_register_types)
```

Base on source code we know that challenge is emulating a linux device via qemu . Look at `pci_notedev_realize` and structure of `static const MemoryRegionOps pci_notedev_mmio_ops` . We know that we can communicate with the device using `pci_notedev_mmio_read` and `pci_notedev_mmio_write`
. `mmio` is stand for memory mapped IO which was well documented in this link https://xz.aliyun.com/t/6562 


After that let take a look at some struct defined in the challenge:
```C
typedef struct NoteEntry {
	uint64_t id;
	uint64_t size;
	uint8_t * content;
	QTAILQ_ENTRY(NoteEntry) next;
} NoteEntry;

typedef struct NoteCmdHdr {
	uint32_t cmd_type;
	uint32_t res;
	uint32_t note_id;
	uint32_t note_size;
	uint32_t encrypt_offset;
	uint32_t new_note_id;
	uint64_t note_addr;
} NoteCmdHdr;

typedef struct PCINoteDevState {
	PCIDevice parent_obj;

	MemoryRegion mmio;

	uint32_t reg[0x20];
	QTAILQ_HEAD(, NoteEntry) notes;
} PCINoteDevState;
```

`PCINoteDevState` is the structure created to manage the state of the note_service device . It contain `PCIDevice` which we dont care for now ,`MemoryRegion mmio` is a important structure which we should really care about . Let break down it structure:
```C
struct MemoryRegion {
    Object parent_obj;

    /* private: */

    /* The following fields should fit in a cache line */
    bool romd_mode;
    bool ram;
    bool subpage;
    bool readonly; /* For RAM regions */
    bool nonvolatile;
    bool rom_device;
    bool flush_coalesced_mmio;
    bool unmergeable;
    uint8_t dirty_log_mask;
    bool is_iommu;
    RAMBlock *ram_block;
    Object *owner;
    /* owner as TYPE_DEVICE. Used for re-entrancy checks in MR access hotpath */
    DeviceState *dev;

    const MemoryRegionOps *ops;
    void *opaque;
    MemoryRegion *container;
    int mapped_via_alias; /* Mapped via an alias, container might be NULL */
    Int128 size;
    hwaddr addr;
    void (*destructor)(MemoryRegion *mr);
    uint64_t align;
    bool terminates;
    bool ram_device;
    bool enabled;
    bool warning_printed; /* For reservations */
    uint8_t vga_logging_count;
    MemoryRegion *alias;
    hwaddr alias_offset;
    int32_t priority;
    QTAILQ_HEAD(, MemoryRegion) subregions;
    QTAILQ_ENTRY(MemoryRegion) subregions_link;
    QTAILQ_HEAD(, CoalescedMemoryRange) coalesced;
    const char *name;
    unsigned ioeventfd_nb;
    MemoryRegionIoeventfd *ioeventfds;
    RamDiscardManager *rdm; /* Only for RAM */

    /* For devices designed to perform re-entrant IO into their own IO MRs */
    bool disable_reentrancy_guard;
};
```

Inside `MemoryRegion` have a pointer to   `struct MemoryRegionOps`. `MemoryRegionOps` is like a vtable that contain function like read, write ,

```C
struct MemoryRegionOps {
    /* Read from the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    uint64_t (*read)(void *opaque,
                     hwaddr addr,
                     unsigned size);
    /* Write to the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    void (*write)(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size);

    MemTxResult (*read_with_attrs)(void *opaque,
                                   hwaddr addr,
                                   uint64_t *data,
                                   unsigned size,
                                   MemTxAttrs attrs);
    MemTxResult (*write_with_attrs)(void *opaque,
                                    hwaddr addr,
                                    uint64_t data,
                                    unsigned size,
                                    MemTxAttrs attrs);

    enum device_endian endianness;
    /* Guest-visible constraints: */
    struct {
        /* If nonzero, specify bounds on access sizes beyond which a machine
         * check is thrown.
         */
        unsigned min_access_size;
        unsigned max_access_size;
        /* If true, unaligned accesses are supported.  Otherwise unaligned
         * accesses throw machine checks.
         */
         bool unaligned;
        /*
         * If present, and returns #false, the transaction is not accepted
         * by the device (and results in machine dependent behaviour such
         * as a machine check exception).
         */
        bool (*accepts)(void *opaque, hwaddr addr,
                        unsigned size, bool is_write,
                        MemTxAttrs attrs);
    } valid;
    /* Internal implementation constraints: */
    struct {
        /* If nonzero, specifies the minimum size implemented.  Smaller sizes
         * will be rounded upwards and a partial result will be returned.
         */
        unsigned min_access_size;
        /* If nonzero, specifies the maximum size implemented.  Larger sizes
         * will be done as a series of accesses with smaller sizes.
         */
        unsigned max_access_size;
        /* If true, unaligned accesses are supported.  Otherwise all accesses
         * are converted to (possibly multiple) naturally aligned accesses.
         */
        bool unaligned;
    } impl;
};
```

as you can see on the source code above the structure of MemoryRegionOps is registered `pci_notedev_mmio_read`,`pci_notedev_mmio_write` for read and write operations.

```C
struct MemoryRegionOps {
    /* Read from the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    uint64_t (*read)(void *opaque,
                     hwaddr addr,
                     unsigned size);
    /* Write to the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    void (*write)(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size);

    MemTxResult (*read_with_attrs)(void *opaque,
                                   hwaddr addr,
                                   uint64_t *data,
                                   unsigned size,
                                   MemTxAttrs attrs);
    MemTxResult (*write_with_attrs)(void *opaque,
                                    hwaddr addr,
                                    uint64_t data,
                                    unsigned size,
                                    MemTxAttrs attrs);

    enum device_endian endianness;
    /* Guest-visible constraints: */
    struct {
        /* If nonzero, specify bounds on access sizes beyond which a machine
         * check is thrown.
         */
        unsigned min_access_size;
        unsigned max_access_size;
        /* If true, unaligned accesses are supported.  Otherwise unaligned
         * accesses throw machine checks.
         */
         bool unaligned;
        /*
         * If present, and returns #false, the transaction is not accepted
         * by the device (and results in machine dependent behaviour such
         * as a machine check exception).
         */
        bool (*accepts)(void *opaque, hwaddr addr,
                        unsigned size, bool is_write,
                        MemTxAttrs attrs);
    } valid;
    /* Internal implementation constraints: */
    struct {
        /* If nonzero, specifies the minimum size implemented.  Smaller sizes
         * will be rounded upwards and a partial result will be returned.
         */
        unsigned min_access_size;
        /* If nonzero, specifies the maximum size implemented.  Larger sizes
         * will be done as a series of accesses with smaller sizes.
         */
        unsigned max_access_size;
        /* If true, unaligned accesses are supported.  Otherwise all accesses
         * are converted to (possibly multiple) naturally aligned accesses.
         */
        bool unaligned;
    } impl;
};
```
Beside that we have `uint32_t reg[0x20];` and `QTAILQ_HEAD(, NoteEntry) notes` . reg could be work as register like edi,esi,... . QTAILQ_HEAD(, NoteEntry) notes is a pointer to the head of the 1 way link list .   


 # Communicating 
Like the link i mentioned above , We know that `Note_service` is a PCI device so we take a look at `/sys/devices/pci0000:00/0000:00:04.0`.

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/d25f3db2-9a4f-40e2-b17f-5612da29d0c0)

right away we can regconize it by `vendor_id` and `device_id`. So we can use this code to mmap a mmio memory region to communicate with the device. 

```C
int main() {
    char buf[0x100];
    int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (fd == -1)
        die("open");

    iomem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (iomem == MAP_FAILED)
        die("mmap");
}
```

# SOURCE CODE ANALYZING

```
static uint64_t pci_notedev_mmio_read(void *opaque, hwaddr reg, unsigned size) {
	PCINoteDevState *ms = opaque;
	uint32_t ret;
	switch (reg) {
		case 0x00:
			do_command(ms);
			ret = 0;
			break;
		case 0x04:
			ret = ms->reg[REG_LOW_CMD_CHAIN_ADDR];
			break;
		case 0x08:
			ret = ms->reg[REG_HIGH_CMD_CHAIN_ADDR];
			break;
		default:
			uint32_t idx = reg / 4;
			if (idx < sizeof(ms->reg)) {
				ret = ms->reg[idx];
			}
			break;
	}

	return ret;
}

static void pci_notedev_mmio_write(void *opaque, hwaddr reg, uint64_t val, unsigned size) {
	PCINoteDevState *ms = opaque;
	switch (reg) {
		case 0x00:
			do_command(ms);
			break;
		case 0x04:
			ms->reg[REG_LOW_CMD_CHAIN_ADDR] = val & 0xfffffff0;
			break;
		case 0x08:
			ms->reg[REG_HIGH_CMD_CHAIN_ADDR] = val;
			break;
		default:
			uint32_t idx = reg / 4;
			if (idx < sizeof(ms->reg)) {
				ms->reg[idx] = val;
			}
			break;
	}
}
```

This 2 function provided us a oob read/write bug when at  `default` case , it check `if (idx < sizeof(ms->reg))` when  `uint32_t reg[0x20]` have size of `4*0x20 = 0x80`, so every value of index in range of 0 - 0x80 should be able to pass the check .
With this 2 bug we can leak data which lie next to `PCINoteDevState` struct  , and also we can use it to over write `QTAILQ_HEAD(, NoteEntry) notes` to point back to PCINoteDevState.mmio.ops  and overwrite it with some address we control and replace 
`pci_notedev_mmio_read` and `pci_notedev_mmio_write` with the system address .

So to do that , first we need to leak the base address of the libc.so.6 . Set a break point at `pci_notedev_mmio_read` to see what we have next to `PCINoteDevState.reg` :

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/8f67c0cd-b787-4974-a07d-23acc56cb59a)

rax is the address of `PCINoteDevState`,`PCINoteDevState + 0x2d0*4` should be `PCINoteDevState.reg` . and `rdx` is the offset which we want to read. 

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/82ad4c9c-69c4-4e97-8d26-8ac7dd7f53d6)

`PCINoteDevState.reg + 0x88` is heap address which is `QTAILQ_HEAD(, NoteEntry) notes`  and after that is address of `qemu_system_x86_64`. If we able to leak this address we shoule be ale to calculate the address of `PCINoteDevState`,`PCINoteDevState.reg` , `PCINoteDevState.mmio.ops` . Nice . Now we need to leak address of libc in order to calculate the address of system .
To do that we can use oob write to write a `qemu_system_x86_64`  GOT address on  `QTAILQ_HEAD(, NoteEntry) notes` and use `read_note` option in `do_command`to leak libc address .

```C
static void do_command(PCINoteDevState *ms){
	uint32_t cnt = 0;
	uint32_t res = 0;
	NoteCmdHdr hdr;
	NoteEntry * note = NULL;
	dma_addr_t cmd_chain_addr = note_addr64(ms->reg[REG_LOW_CMD_CHAIN_ADDR], ms->reg[REG_HIGH_CMD_CHAIN_ADDR]);
	

	for (cnt = 0; cnt < 0x20; ++cnt) {
		memset(&hdr, 0, sizeof hdr);
		cpu_physical_memory_rw(cmd_chain_addr, &hdr, sizeof(NoteCmdHdr), 0);
		le32_to_cpus(&hdr.cmd_type);
		le32_to_cpus(&hdr.note_id);
		le32_to_cpus(&hdr.note_size);
		le32_to_cpus(&hdr.encrypt_offset);
		le32_to_cpus(&hdr.new_note_id);
		le64_to_cpus(&hdr.note_addr);
		hdr.note_size &= 0xfff;
		hdr.encrypt_offset &= 0xfff;
		res = NOTE_SUCCESS;
		switch (hdr.cmd_type) {
			case CMD_SUBMIT_NOTE:
				note = g_malloc(sizeof(NoteEntry));
				note->id = hdr.note_id;
				note->size = hdr.note_size;
				note->content = g_malloc(note->size);
				memset(note->content, 0, note->size);

				cpu_physical_memory_rw(hdr.note_addr, note->content, note->size, 0);

				QTAILQ_INSERT_TAIL(&ms->notes, note, next);

				break;

			case CMD_DELETE_NOTE:
				note = search_for_notes(ms, hdr.note_id);
				if (note == NULL) {
					res = NOTE_FAIL;
					break;
				}

				QTAILQ_REMOVE(&ms->notes, note, next);
				if (note->content) {
					g_free(note->content);
				}
				g_free(note);

				break;

			case CMD_READ_NOTE:
				note = search_for_notes(ms, hdr.note_id);
				if (note == NULL) {
					res = NOTE_FAIL;
					break;
				}
				uint32_t size = hdr.note_size;
				
				if (size > note->size) {
					size = note->size;
				}

				cpu_physical_memory_rw(hdr.note_addr, note->content, size, 1);

				break;

			case CMD_EDIT_NOTE:
				note = search_for_notes(ms, hdr.note_id);
				if (note == NULL) {
					res = NOTE_FAIL;
					break;
				}
				
				if (hdr.note_size <= note->size) {
					cpu_physical_memory_rw(hdr.note_addr, note->content, hdr.note_size, 0);
				} 
				else {
					g_free(note->content);
					note->size = hdr.note_size;
					note->content = g_malloc(note->size);
					memset(note->content, 0, note->size);
					cpu_physical_memory_rw(hdr.note_addr, note->content, note->size, 0);
				}
				break;
			
			case CMD_DUPLICATE_NOTE:
				NoteEntry *dup_note = search_for_notes(ms, hdr.note_id);
				if (dup_note == NULL) {
					res = NOTE_FAIL;
					break;
				}
				note = g_malloc(sizeof(NoteEntry));
				note->id = hdr.new_note_id;
				note->size = hdr.note_size;
				note->content = g_malloc(note->size);
				memset(note->content, 0, note->size);
				
				cpu_physical_memory_rw(hdr.note_addr, note->content, note->size, 0);
				
				uint32_t size_to_copy = dup_note->size;
				if (size_to_copy > note->size) {
					size_to_copy = note->size;
				}

				memcpy(note->content, dup_note->content, size_to_copy);
				QTAILQ_INSERT_TAIL(&ms->notes, note, next);
				break;

			case CMD_ENCRYPT_NOTE:
				note = search_for_notes(ms, hdr.note_id);
				if (note == NULL) {
					res = NOTE_FAIL;
					break;
				}

				if (hdr.encrypt_offset >= note->size) {
					res = NOTE_FAIL;
					break;
				}

				uint32_t size_to_encrypt = note->size;
				if (size_to_copy > hdr.note_size) {
					size_to_copy = hdr.note_size;
				}

				if (size_to_copy + hdr.encrypt_offset >= note->size) {
					size_to_copy = note->size - hdr.encrypt_offset;
				}

				uint8_t * secret = g_malloc(hdr.note_size);
				memset(secret, 0, hdr.note_size);

				cpu_physical_memory_rw(hdr.note_addr, secret, hdr.note_size, 0);
				
				

				for (uint32_t i = 0; i < size_to_encrypt; ++i) {
					note->content[i + hdr.encrypt_offset] ^= secret[i];
				}
				break;
			
			case CMD_RESET:
				res = NOTE_RESET;
				res = cpu_to_le32(res);
				cpu_physical_memory_rw(cmd_chain_addr + 4, &res, 4, 0);
				pci_notedev_reset(ms);
				return;
		}
		
		res = cpu_to_le32(res);
		cpu_physical_memory_rw(cmd_chain_addr + 4, &res, 4, 0);
		if (hdr.cmd_type == CMD_END_CHAIN) {
			break;
		}
		cmd_chain_addr += sizeof(NoteCmdHdr);
	}	
}
```

to summarize `do_command` will read from `cmd_chain_addr` `to NoteCmdHdr hdr` and call the function corresponding to `hdr.cmd_type`, cmd_chain_addr is a physical address and we can control this address via write into `PCINoteDevState.reg[REG_LOW_CMD_CHAIN_ADDR]`. to do this we can mmap a page and use it virtual address to calculate the physical adress  and use it for our purposes .
. In the link above already have a function which help us convert virtual address to physical address.

`the code was taken from challenge WU`

```C
uint64_t virt2phys(void* p) {
    uint64_t virt = (uint64_t)p;
    assert((virt & 0xfff) == 0);
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1)
            die("open");

    uint64_t offset = (virt / 0x1000) * 8;
    lseek(fd, offset, SEEK_SET);
    uint64_t phys;
    if (read(fd, &phys, 8 ) != 8)
            die("read");
    
    assert(phys & (1ULL << 63));
    phys = (phys & ((1ULL << 54) - 1)) * 0x1000;
    return phys;
}
```

`cpu_physical_memory_rw` is a function which can read or write directly into physical address , arguments in this order `cpu_physical_memory_rw(hwaddr addr, uint8_t *buf,int len, int is_write)` . Where addr is physical address buffer and buf can be virtual address which can be read from or write to.

# EXPLOIT 
 
Inorder to leak leak libc address we can use the register field as a fake note and overwrite the note head pointer to our fake chunk and then replcace the fake_note.content with a `qemu_system_x86_64` GOT address to leak the address of libc , and then we can create a another fake_note so we can write into `PCINoteDevState.mmio.ops`

Take a look in IDA we can easyly get the offset of `PCINoteDevState.mmio` and `PCINoteDevState.mmio.ops` 

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/9c9ab430-d67d-41aa-9315-05ac59cfba45)

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/6446e0af-0100-40d8-871f-3a6efbe012c9)

 so after leak heap addres and calculate the `PCINoteDevState` address we can add that address with 0xa80 should be address of `PCINoteDevState.mmio.ops` overwrite this pointer so it point to our contolled buffer which contain the system address . And we can see that the read and wite funtion of `ops` was taking `opaque`  as the first argument . By debugging we can know this address was the address of `PCINoteDevState` so just make another abitary read to the address of `PCINoteDevState` and inject our command into it . We are unable to get a shell by calling system("/bin/sh\x00"); the system will be just hang there forever , but we could do some thing like inject command and make a easy reverse shell but by checking the docker file we are unable to do so cause the docker have no command such `nc` or `socat`. So in this case we can just cat the flag . The exploit script was originaly from other player . 

challenge and dockerfile :

 https://drive.google.com/drive/folders/1CyojrTtEXydTKvF-vePM22316fZzdJ6Q?usp=sharing










