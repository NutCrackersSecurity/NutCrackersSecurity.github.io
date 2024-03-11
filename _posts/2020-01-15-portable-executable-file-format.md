---
layout: post
title: "PE Portable Executable File Format"
date: 2020-01-15 13:02:00 -0500
categories: reverse PE
tags: windows reverse-engineering asm PE
image:
  path: /assets/img/headers/pe-file/PEXE.png
---

## PE Portable Executable File Format

Hello, my name is Moldovan Darius, also known as [@T3jv1l](https://twitter.com/T3jv1l). I'm using the calc.exe executable file for this analysis. PE is the default file format for Win32. Win32 executables all employ the PE file format. All 32-bit DLLs, COM files, OCX controls, Control Panel Applets (.CPL files), and.NET executables are in the PE format. PE file format is used by even NT kernel mode drivers.

"PE format is a data structure that encapsulates the information required for the Windows OS loader to manage the wrapped executable code," according to Wikipedia. This comprises API export and import tables, resource management data, dynamic library references for linking, and thread-local storage (TLS) data. EXE, DLL, SYS (device driver), and other file types are stored in the PE format in NT operating systems. According to the Extensible Firmware Interface (EFI) specification, PE is the default executable format used in EFI settings.

Ones of the PE data structures is:

- _IMAGE_DOS_HEADER
- DOS STUB
- _IMAGE_NT_HEADER

image directory entry, image optional header, and image file header (*).

The MS-DOS header, which takes up the first 64 bytes of the PE file format, is called `_IMAGE_DOS_HEADER` when we begin. It is there in case DOS is used to run the program, allowing DOS to run the DOS stub that is put right after the header and recognize the program as a genuine executable. A full-fledged DOS application can be used instead of the typical DOS stub, which often merely prints a string saying something like "This program must be run under Microsoft Windows."
```c
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	USHORT e_magic;                 // Magic number
	    USHORT e_cblp;              // Bytes on last page of file
	    USHORT e_cp;                // Pages in file
	    USHORT e_crlc;              // Relocations
	    USHORT e_cparhdr;           // Size of header in paragraphs
	    USHORT e_minalloc;          // Minimum extra paragraphs needed
	    USHORT e_maxalloc;          // Maximum extra paragraphs needed
	    USHORT e_ss;                // Initial (relative) SS value
	    USHORT e_sp;                // Initial SP value
	    USHORT e_csum;              // Checksum
	    USHORT e_ip;                // Initial IP value
	    USHORT e_cs;                // Initial (relative) CS value
	    USHORT e_lfarlc;            // File address of relocation table
	    USHORT e_ovno;              // Overlay number
	    USHORT e_res[4];            // Reserved words
	    USHORT e_oemid;             // OEM identifier (for e_oeminfo)
	    USHORT e_oeminfo;           // OEM information; e_oemid specific
	    USHORT e_res2[10];          // Reserved words
	    LONG   e_lfanew;            // File address of new exe header
	  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

The magic portion of the MS-DOS header in the PE file has the value `4D 5A` (MZ = Mark Zbikowsky, one of the early designers of MS-DOS).

Before using WinDGB to evaluate this Header, let's talk about what ImageBaseAddress is. This is crucial because we need to discover the address where the `_IMAGE_DOS_HEADER` is located. The address at which an executable file will be memory-mapped to a particular region in memory is called `ImageBase`.

The most recent version of Windows has the `ImageBaseAddress=0x00400000`, according to MSDN. If everything is okay, let's begin.

Let's use `ImageBaseAddress` to determine where calc.exe's start address is now. Type `lmv m image00400000` with this command we inspect closely and the output will be displayed verbosely.

![pe-file](/assets/img/headers/pe-file/PE2.png)

The PE file (calc.exe)'s image base address is currently `0x00270000`.

The contents of `_IMAGE_DOS_HEADER` are now visible. It is comparable to the previous C syntax. We have the `MZ` string magic number `0x5A4D`.

![pe-file](/assets/img/headers/pe-file/PE3.png)

We now need to determine `e_lfanew` 's offset. You may be wondering what this e_lfanew is. By indexing the e_lfanew field of the MS-DOS header, the PE file header can be found. The e_lfanew column only provides the file offset; to get the real memory-mapped address, add the file's memory-mapped base address. Remember that `PE` appears in the signature, which is what we are looking for.

The `Image_File_Header`, `Image_Optional_Header`, and `Image_Directory_Entry` are the three primary components of the main PE Header, which is a structure of type `IMAGE_NT_HEADERS`.

![pe-file](/assets/img/headers/pe-file/PE4.png)

The `n` in `0n232` indicates that the number is base 10 and `x` will indicate base 16 (hex). Made a simple calculation to find the "PE string"

![pe-file](/assets/img/headers/pe-file/PE5.png)

Let's now move on to the `_IMAGE_NT_HEADER`. Since this is the primary PE header and contains the PE Signature `0x4550`, `IMAGE_FILE_HEADER`, `IMAGE_OPTIONAL_HEADER` and `_IMAGE_DIRECTORY_ENTRY_[*]`, there is no need to go into great detail about it. 

![pe-file](/assets/img/headers/pe-file/PE6.png)

The `_IMAGE_FILE_HEADER` Section continues. At address 0x002700e8, we must add 4 bytes in order to access this area.

![pe-file](/assets/img/headers/pe-file/PE7.png)

Let's look at the contents of the PE file's `_IMAGE_FILE_HEADER` section.

![pe-file](/assets/img/headers/pe-file/PE8.png)

Machine section contain CPU IDs, we can see we have `0x14c` that means we use Intel I386. 

![pe-file](/assets/img/headers/pe-file/PE0.png)

- `NumberOfSections`. The number of sections there are in the file.

- `TimeDateStamp`. the moment at which this file was created by the linker (or compiler for an OBJ file).

- `PointerToSymbolTable`. Only OBJ and PE files with COFF debug information use this field.

- `NumberOfSymbols`. how many symbols there are in the COFF symbol table. Check the COFF Simbol Table for more details.

- `SizeOfOptionalHeader`. the dimensions of any optional header that could be used after this one. The field in OBJs is 0. It is the size of the structure called IMAGE_OPTIONAL_HEADER that comes after this structure in executables.

- `Characteristics`. informational flags for the file.

The `_IMAGE_OPTIONAL_HEADER` section follows. At position `0x002700ec`, we must add 20 bytes (0x14) in order to reach this part.

![pe-file](/assets/img/headers/pe-file/PE9.png)

Let's look at what the _IMAGE_OPTIONAL_HEADER section contains.

![pe-file](/assets/img/headers/pe-file/PE10.png)

- `Magic numeber` 0x10b. The optional header magic number determines whether an image is a PE32 (0x10b) or PE32+(0x20b) executable.

- `MajorLinkerVersion`, MinorLinkerVersion. Indicates version of the linker that linked this image.

- `SizeOfCode`. Size of executable code.

- `SizeOfInitializedData`. Size of initialized data.

- `SizeOfUninitializedData`.. Size of uninitialized data.

- `AddressOfEntryPoint`. Defined in the PECOFF format for executable files refers to location in memory where the first instruction of execution will be placed

- `BaseOfCode`. Relative offset of code (".text" section) in loaded image.

- `BaseOfData`. Relative offset of uninitialized data (".bss" section) in loaded image

- `ImageBase`. Preferred base address in the address space of a process to map the executable image to. The linker defaults to 0x00400000, but you can override the default with the -BASE: linker switch

- `SectionAlignment`. Each section is loaded into the address space of a process sequentially, beginning at ImageBase. SectionAlignment dictates the minimum amount of space a section can occupy when loaded--that is, sections are aligned on SectionAlignment boundaries.

- `FileAlignment`. Minimum granularity of chunks of information within the image file prior to loading.

- `MajorOperatingSystemVersion`. Indicates the major version of the Windows NT operating system.

- `MinorOperatingSystemVersion`. Indicates the minor version of the Windows NT operating system.

- `MajorImageVersion`. Used to indicate the major version number of the application.

- `MinorImageVersion`. Used to indicate the minor version number of the application.

- `MajorSubsystemVersion`. Indicates the Windows NT Win32 subsystem major version number.

- `MinorSubsystemVersion`. Indicates the Windows NT Win32 subsystem minor version number.

- `Win32VersionValues`. Defines a version-information resource. The resource contains such information about the file as its version number, its intended operating system, and its original filename

- `SizeOfImage`. Indicates the amount of address space to reserve in the address space for the loaded executable image. This number is influenced greatly by SectionAlignment.

- `SizeOfHeaders`. This field indicates how much space in the file is used for representing all the file headers, including the MS-DOS header, PE file header, PE optional header, and PE section headers. The section bodies begin at this location in the file.

- `CheckSum`. A checksum value is used to validate the executable file at load time. The value is set and verified by the linker. The algorithm used for creating these checksum values is proprietary information and will not be published.

- `Subsystem`. Field used to identify the target subsystem for this executable. Each of the possible subsystem values are listed in the WINNT.H file immediately after the IMAGE_OPTIONAL_HEADER structure.

- `DllCharacteristics`. Flags used to indicate if a DLL image includes entry points for process and thread initialization and termination.

- `SizeOfStackReserve`, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit. These fields control the amount of address space to reserve and commit for the stack and default heap. Both the stack and heap have default values of 1 page committed and 16 pages reserved. These values are set with the linker switches -STACKSIZE: and -HEAPSIZE: .

- `LoaderFlags`. Tells the loader whether to break on load, debug on load, or the default, which is to let things run normally.

- `NumberOfRvaAndSizes`. This field identifies the length of the DataDirectory array that follows. It is important to note that this field is used to identify the size of the array, not the number of valid entries in the array

- `DataDirectory`. The data directory indicates where to find other important components of executable information in the file. It is really nothing more than an array of IMAGE_DATA_DIRECTORY structures that are located at the end of the optional header structure. The current PE file format defines 16 possible data directories, 11 of which are now being used.

Next Section is `_IMAGE_DATA_DIRECTORY`. To access this section we need to add 96 bytes at `0x002700100` address.

![pe-file](/assets/img/headers/pe-file/PE11.png)

The address for the image data directory is currently `0x002700160`. Display this header 16 times.

![pe-file](/assets/img/headers/pe-file/PE12.png)

A 16 array `_IMAGE_DATA_DIRECTORY` structure represents the data directory. Each component of the data directory is a structure with the name `IMAGE_DATA_DIRECTORY` and the definition given below:
```c
struct IMAGE_DATA_DIRECTORY STRUCT{
	VirtualAddress dd ?
        ISize dd ?
  }
```

I hope you like to read about this topic Reverse Engineering Stuff.

## Reference

[https://blog.kowalczyk.info/articles/pefileformat.html](https://blog.kowalczyk.info/articles/pefileformat.html)

[https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/](https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/)

[https://www.ixiacom.com/company/blog/debugging-malware-windbg](https://www.ixiacom.com/company/blog/debugging-malware-windbg)

[https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN)

[https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#general-concepts](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#general-concepts)
