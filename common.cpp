//==================================
// PEDUMP - Matt Pietrek 1997
// FILE: COMMON.C
//==================================

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "common.h"
#include "symboltablesupport.h"
#include "extrnvar.h"

PIMAGE_DEBUG_MISC g_pMiscDebugInfo = 0;
PDWORD g_pCVHeader = 0;
PIMAGE_COFF_SYMBOLS_HEADER g_pCOFFHeader = 0;
COFFSymbolTable * g_pCOFFSymbolTable = 0;

/*----------------------------------------------------------------------------*/
//
// Header related stuff
//
/*----------------------------------------------------------------------------*/

typedef struct
{
    WORD    flag;
    PSTR    name;
} WORD_FLAG_DESCRIPTIONS;

typedef struct
{
    DWORD   flag;
    PSTR    name;
} DWORD_FLAG_DESCRIPTIONS;

// Bitfield values and names for the IMAGE_FILE_HEADER flags
WORD_FLAG_DESCRIPTIONS ImageFileHeaderCharacteristics[] = 
{
{ IMAGE_FILE_RELOCS_STRIPPED, "RELOCS_STRIPPED" },
{ IMAGE_FILE_EXECUTABLE_IMAGE, "EXECUTABLE_IMAGE" },
{ IMAGE_FILE_LINE_NUMS_STRIPPED, "LINE_NUMS_STRIPPED" },
{ IMAGE_FILE_LOCAL_SYMS_STRIPPED, "LOCAL_SYMS_STRIPPED" },
{ IMAGE_FILE_AGGRESIVE_WS_TRIM, "AGGRESIVE_WS_TRIM" },
// { IMAGE_FILE_MINIMAL_OBJECT, "MINIMAL_OBJECT" }, // Removed in NT 3.5
// { IMAGE_FILE_UPDATE_OBJECT, "UPDATE_OBJECT" },   // Removed in NT 3.5
// { IMAGE_FILE_16BIT_MACHINE, "16BIT_MACHINE" },   // Removed in NT 3.5
{ IMAGE_FILE_BYTES_REVERSED_LO, "BYTES_REVERSED_LO" },
{ IMAGE_FILE_32BIT_MACHINE, "32BIT_MACHINE" },
{ IMAGE_FILE_DEBUG_STRIPPED, "DEBUG_STRIPPED" },
// { IMAGE_FILE_PATCH, "PATCH" },
{ IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP" },
{ IMAGE_FILE_NET_RUN_FROM_SWAP, "NET_RUN_FROM_SWAP" },
{ IMAGE_FILE_SYSTEM, "SYSTEM" },
{ IMAGE_FILE_DLL, "DLL" },
{ IMAGE_FILE_UP_SYSTEM_ONLY, "UP_SYSTEM_ONLY" },
{ IMAGE_FILE_BYTES_REVERSED_HI, "BYTES_REVERSED_HI" }
};

#define NUMBER_IMAGE_HEADER_FLAGS \
    (sizeof(ImageFileHeaderCharacteristics) / sizeof(WORD_FLAG_DESCRIPTIONS))

//
// Dump the IMAGE_FILE_HEADER for a PE file or an OBJ
//
void DumpHeader(PIMAGE_FILE_HEADER pImageFileHeader)
{
    UINT headerFieldWidth = 30;
    UINT i;
    
    printf("File Header\n");

    printf("  %-*s%04X (%s)\n", headerFieldWidth, "Machine:", 
                pImageFileHeader->Machine,
                GetMachineTypeName(pImageFileHeader->Machine) );
    printf("  %-*s%04X\n", headerFieldWidth, "Number of Sections:",
                pImageFileHeader->NumberOfSections);
    printf("  %-*s%08X -> %s", headerFieldWidth, "TimeDateStamp:",
                pImageFileHeader->TimeDateStamp,
                ctime((time_t *)&pImageFileHeader->TimeDateStamp));
    printf("  %-*s%08X\n", headerFieldWidth, "PointerToSymbolTable:",
                pImageFileHeader->PointerToSymbolTable);
    printf("  %-*s%08X\n", headerFieldWidth, "NumberOfSymbols:",
                pImageFileHeader->NumberOfSymbols);
    printf("  %-*s%04X\n", headerFieldWidth, "SizeOfOptionalHeader:",
                pImageFileHeader->SizeOfOptionalHeader);
    printf("  %-*s%04X\n", headerFieldWidth, "Characteristics:",
                pImageFileHeader->Characteristics);
    for ( i=0; i < NUMBER_IMAGE_HEADER_FLAGS; i++ )
    {
        if ( pImageFileHeader->Characteristics & 
             ImageFileHeaderCharacteristics[i].flag )
            printf( "    %s\n", ImageFileHeaderCharacteristics[i].name );
    }
}

#ifndef	IMAGE_DLLCHARACTERISTICS_WDM_DRIVER
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER  0x2000     // Driver uses WDM model
#endif

// Marked as obsolete in MSDN CD 9
// Bitfield values and names for the DllCharacteritics flags
WORD_FLAG_DESCRIPTIONS DllCharacteristics[] = 
{
{ IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "WDM_DRIVER" },
};
#define NUMBER_DLL_CHARACTERISTICS \
    (sizeof(DllCharacteristics) / sizeof(WORD_FLAG_DESCRIPTIONS))

#if 0
// Marked as obsolete in MSDN CD 9
// Bitfield values and names for the LoaderFlags flags
DWORD_FLAG_DESCRIPTIONS LoaderFlags[] = 
{
{ IMAGE_LOADER_FLAGS_BREAK_ON_LOAD, "BREAK_ON_LOAD" },
{ IMAGE_LOADER_FLAGS_DEBUG_ON_LOAD, "DEBUG_ON_LOAD" }
};
#define NUMBER_LOADER_FLAGS \
    (sizeof(LoaderFlags) / sizeof(DWORD_FLAG_DESCRIPTIONS))
#endif

// Names of the data directory elements that are defined
char *ImageDirectoryNames[] = {
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
    "DEBUG", "COPYRIGHT", "GLOBALPTR", "TLS", "LOAD_CONFIG",
    "BOUND_IMPORT", "IAT",  // These two entries added for NT 3.51
	"DELAY_IMPORT" };		// This entry added in NT 5

#define NUMBER_IMAGE_DIRECTORY_ENTRYS \
    (sizeof(ImageDirectoryNames)/sizeof(char *))

//
// Dump the IMAGE_OPTIONAL_HEADER from a PE file
//
void DumpOptionalHeader(PIMAGE_OPTIONAL_HEADER optionalHeader)
{
    UINT width = 30;
    char *s;
    UINT i;
    
    printf("Optional Header\n");
    
    printf("  %-*s%04X\n", width, "Magic", optionalHeader->Magic);
    printf("  %-*s%u.%02u\n", width, "linker version",
        optionalHeader->MajorLinkerVersion,
        optionalHeader->MinorLinkerVersion);
    printf("  %-*s%X\n", width, "size of code", optionalHeader->SizeOfCode);
    printf("  %-*s%X\n", width, "size of initialized data",
        optionalHeader->SizeOfInitializedData);
    printf("  %-*s%X\n", width, "size of uninitialized data",
        optionalHeader->SizeOfUninitializedData);
    printf("  %-*s%X\n", width, "entrypoint RVA",
        optionalHeader->AddressOfEntryPoint);
    printf("  %-*s%X\n", width, "base of code", optionalHeader->BaseOfCode);
#ifndef _WIN64
    printf("  %-*s%X\n", width, "base of data", optionalHeader->BaseOfData);
#endif
    printf("  %-*s%X\n", width, "image base", optionalHeader->ImageBase);

    printf("  %-*s%X\n", width, "section align",
        optionalHeader->SectionAlignment);
    printf("  %-*s%X\n", width, "file align", optionalHeader->FileAlignment);
    printf("  %-*s%u.%02u\n", width, "required OS version",
        optionalHeader->MajorOperatingSystemVersion,
        optionalHeader->MinorOperatingSystemVersion);
    printf("  %-*s%u.%02u\n", width, "image version",
        optionalHeader->MajorImageVersion,
        optionalHeader->MinorImageVersion);
    printf("  %-*s%u.%02u\n", width, "subsystem version",
        optionalHeader->MajorSubsystemVersion,
        optionalHeader->MinorSubsystemVersion);
    printf("  %-*s%X\n", width, "Win32 Version",
    	optionalHeader->Win32VersionValue);
    printf("  %-*s%X\n", width, "size of image", optionalHeader->SizeOfImage);
    printf("  %-*s%X\n", width, "size of headers",
            optionalHeader->SizeOfHeaders);
    printf("  %-*s%X\n", width, "checksum", optionalHeader->CheckSum);
    switch( optionalHeader->Subsystem )
    {
        case IMAGE_SUBSYSTEM_NATIVE: s = "Native"; break;
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: s = "Windows GUI"; break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: s = "Windows character"; break;
        case IMAGE_SUBSYSTEM_OS2_CUI: s = "OS/2 character"; break;
        case IMAGE_SUBSYSTEM_POSIX_CUI: s = "Posix character"; break;
        default: s = "unknown";
    }
    printf("  %-*s%04X (%s)\n", width, "Subsystem",
            optionalHeader->Subsystem, s);

// Marked as obsolete in MSDN CD 9
    printf("  %-*s%04X\n", width, "DLL flags",
            optionalHeader->DllCharacteristics);
    for ( i=0; i < NUMBER_DLL_CHARACTERISTICS; i++ )
    {
        if ( optionalHeader->DllCharacteristics & 
             DllCharacteristics[i].flag )
            printf( "  %-*s%s", width, " ", DllCharacteristics[i].name );
    }
    if ( optionalHeader->DllCharacteristics )
        printf("\n");

    printf("  %-*s%X\n", width, "stack reserve size",
        optionalHeader->SizeOfStackReserve);
    printf("  %-*s%X\n", width, "stack commit size",
        optionalHeader->SizeOfStackCommit);
    printf("  %-*s%X\n", width, "heap reserve size",
        optionalHeader->SizeOfHeapReserve);
    printf("  %-*s%X\n", width, "heap commit size",
        optionalHeader->SizeOfHeapCommit);

#if 0
// Marked as obsolete in MSDN CD 9
    printf("  %-*s%08X\n", width, "loader flags",
        optionalHeader->LoaderFlags);

    for ( i=0; i < NUMBER_LOADER_FLAGS; i++ )
    {
        if ( optionalHeader->LoaderFlags & 
             LoaderFlags[i].flag )
            printf( "  %s", LoaderFlags[i].name );
    }
    if ( optionalHeader->LoaderFlags )
        printf("\n");
#endif

    printf("  %-*s%X\n", width, "RVAs & sizes",
        optionalHeader->NumberOfRvaAndSizes);

    printf("\nData Directory\n");
    for ( i=0; i < optionalHeader->NumberOfRvaAndSizes; i++)
    {
        printf( "  %-12s rva: %08X  size: %08X\n",
            (i >= NUMBER_IMAGE_DIRECTORY_ENTRYS)
                ? "unused" : ImageDirectoryNames[i], 
            optionalHeader->DataDirectory[i].VirtualAddress,
            optionalHeader->DataDirectory[i].Size);
    }
}

PSTR GetMachineTypeName( WORD wMachineType )
{
    switch( wMachineType )
    {
        case IMAGE_FILE_MACHINE_I386: 	return "i386";
        // case IMAGE_FILE_MACHINE_I860:return "i860";
        case IMAGE_FILE_MACHINE_R3000:  return "R3000";
		case 160:                       return "R3000 big endian";
        case IMAGE_FILE_MACHINE_R4000:  return "R4000";
		case IMAGE_FILE_MACHINE_R10000: return "R10000";
        case IMAGE_FILE_MACHINE_ALPHA:  return "Alpha";
        case IMAGE_FILE_MACHINE_POWERPC:return "PowerPC";
        default:    					return "unknown";
    }
}


/*----------------------------------------------------------------------------*/
//
// Section related stuff
//
/*----------------------------------------------------------------------------*/

//
// These aren't defined in the NT 4.0 WINNT.H, so we'll define them here
//
#ifndef IMAGE_SCN_TYPE_DSECT
#define IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
#endif
#ifndef IMAGE_SCN_TYPE_NOLOAD
#define IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
#endif
#ifndef IMAGE_SCN_TYPE_GROUP
#define IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.
#endif
#ifndef IMAGE_SCN_TYPE_COPY
#define IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.
#endif
#ifndef IMAGE_SCN_TYPE_OVER
#define IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.
#endif
#ifndef IMAGE_SCN_MEM_PROTECTED
#define IMAGE_SCN_MEM_PROTECTED              0x00004000
#endif
#ifndef IMAGE_SCN_MEM_SYSHEAP
#define IMAGE_SCN_MEM_SYSHEAP                0x00010000
#endif

// Bitfield values and names for the IMAGE_SECTION_HEADER flags
DWORD_FLAG_DESCRIPTIONS SectionCharacteristics[] = 
{

{ IMAGE_SCN_TYPE_DSECT, "DSECT" },
{ IMAGE_SCN_TYPE_NOLOAD, "NOLOAD" },
{ IMAGE_SCN_TYPE_GROUP, "GROUP" },
{ IMAGE_SCN_TYPE_NO_PAD, "NO_PAD" },
{ IMAGE_SCN_TYPE_COPY, "COPY" },
{ IMAGE_SCN_CNT_CODE, "CODE" },
{ IMAGE_SCN_CNT_INITIALIZED_DATA, "INITIALIZED_DATA" },
{ IMAGE_SCN_CNT_UNINITIALIZED_DATA, "UNINITIALIZED_DATA" },
{ IMAGE_SCN_LNK_OTHER, "OTHER" },
{ IMAGE_SCN_LNK_INFO, "INFO" },
{ IMAGE_SCN_TYPE_OVER, "OVER" },
{ IMAGE_SCN_LNK_REMOVE, "REMOVE" },
{ IMAGE_SCN_LNK_COMDAT, "COMDAT" },
{ IMAGE_SCN_MEM_PROTECTED, "PROTECTED" },
{ IMAGE_SCN_MEM_FARDATA, "FARDATA" },
{ IMAGE_SCN_MEM_SYSHEAP, "SYSHEAP" },
{ IMAGE_SCN_MEM_PURGEABLE, "PURGEABLE" },
{ IMAGE_SCN_MEM_LOCKED, "LOCKED" },
{ IMAGE_SCN_MEM_PRELOAD, "PRELOAD" },
{ IMAGE_SCN_LNK_NRELOC_OVFL, "NRELOC_OVFL" },
{ IMAGE_SCN_MEM_DISCARDABLE, "DISCARDABLE" },
{ IMAGE_SCN_MEM_NOT_CACHED, "NOT_CACHED" },
{ IMAGE_SCN_MEM_NOT_PAGED, "NOT_PAGED" },
{ IMAGE_SCN_MEM_SHARED, "SHARED" },
{ IMAGE_SCN_MEM_EXECUTE, "EXECUTE" },
{ IMAGE_SCN_MEM_READ, "READ" },
{ IMAGE_SCN_MEM_WRITE, "WRITE" },
};

#define NUMBER_SECTION_CHARACTERISTICS \
    (sizeof(SectionCharacteristics) / sizeof(DWORD_FLAG_DESCRIPTIONS))

//
// Dump the section table from a PE file or an OBJ
//
void DumpSectionTable(PIMAGE_SECTION_HEADER section,
                      unsigned cSections,
                      BOOL IsEXE)
{
    unsigned i, j;
	PSTR pszAlign;

    printf("Section Table\n");
    
    for ( i=1; i <= cSections; i++, section++ )
    {
        printf( "  %02X %-8.8s  %s: %08X  VirtAddr:  %08X\n",
                i, section->Name,
                IsEXE ? "VirtSize" : "PhysAddr",
                section->Misc.VirtualSize, section->VirtualAddress);
        printf( "    raw data offs:   %08X  raw data size: %08X\n",
                section->PointerToRawData, section->SizeOfRawData );
        printf( "    relocation offs: %08X  relocations:   %08X\n",
                section->PointerToRelocations, section->NumberOfRelocations );
        printf( "    line # offs:     %08X  line #'s:      %08X\n",
                section->PointerToLinenumbers, section->NumberOfLinenumbers );
        printf( "    characteristics: %08X\n", section->Characteristics);

        printf("    ");
        for ( j=0; j < NUMBER_SECTION_CHARACTERISTICS; j++ )
        {
            if ( section->Characteristics & 
                SectionCharacteristics[j].flag )
                printf( "  %s", SectionCharacteristics[j].name );
        }
		
		switch( section->Characteristics & IMAGE_SCN_ALIGN_64BYTES )
		{
			case IMAGE_SCN_ALIGN_1BYTES: pszAlign = "ALIGN_1BYTES"; break;
			case IMAGE_SCN_ALIGN_2BYTES: pszAlign = "ALIGN_2BYTES"; break;
			case IMAGE_SCN_ALIGN_4BYTES: pszAlign = "ALIGN_4BYTES"; break;
			case IMAGE_SCN_ALIGN_8BYTES: pszAlign = "ALIGN_8BYTES"; break;
			case IMAGE_SCN_ALIGN_16BYTES: pszAlign = "ALIGN_16BYTES"; break;
			case IMAGE_SCN_ALIGN_32BYTES: pszAlign = "ALIGN_32BYTES"; break;
			case IMAGE_SCN_ALIGN_64BYTES: pszAlign = "ALIGN_64BYTES"; break;
			default: pszAlign = "ALIGN_DEFAULT(16)"; break;
		}
		printf( "  %s", pszAlign );

        printf("\n\n");
    }
}

//
// Given a section name, look it up in the section table and return a
// pointer to the start of its raw data area.
//
LPVOID GetSectionPtr(PSTR name, PIMAGE_NT_HEADERS pNTHeader, DWORD imageBase)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    unsigned i;
    
    for ( i=0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++ )
    {
        if (strncmp((char *)section->Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0)
            return (LPVOID)(section->PointerToRawData + imageBase);
    }
    
    return 0;
}

LPVOID GetPtrFromRVA( DWORD rva, PIMAGE_NT_HEADERS pNTHeader, DWORD imageBase )
{
	PIMAGE_SECTION_HEADER pSectionHdr;
	INT delta;
		
	pSectionHdr = GetEnclosingSectionHeader( rva, pNTHeader );
	if ( !pSectionHdr )
		return 0;

	delta = (INT)(pSectionHdr->VirtualAddress-pSectionHdr->PointerToRawData);
	return (PVOID) ( imageBase + rva - delta );
}

//
// Given a section name, look it up in the section table and return a
// pointer to its IMAGE_SECTION_HEADER
//
PIMAGE_SECTION_HEADER GetSectionHeader(PSTR name, PIMAGE_NT_HEADERS pNTHeader)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    unsigned i;
    
    for ( i=0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++ )
    {
        if ( 0 == strncmp((char *)section->Name,name,IMAGE_SIZEOF_SHORT_NAME) )
            return section;
    }
    
    return 0;
}

//
// Given an RVA, look up the section header that encloses it and return a
// pointer to its IMAGE_SECTION_HEADER
//
PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva,
                                                PIMAGE_NT_HEADERS pNTHeader)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    unsigned i;
    
    for ( i=0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++ )
    {
        // Is the RVA within this section?
        if ( (rva >= section->VirtualAddress) && 
             (rva < (section->VirtualAddress + section->Misc.VirtualSize)))
            return section;
    }
    
    return 0;
}

PIMAGE_COFF_SYMBOLS_HEADER PCOFFDebugInfo = 0;

char *SzDebugFormats[] = {
"UNKNOWN/BORLAND","COFF","CODEVIEW","FPO","MISC","EXCEPTION","FIXUP",
"OMAP_TO_SRC", "OMAP_FROM_SRC"};

//
// Dump the debug directory array
//
void DumpDebugDirectory(PIMAGE_DEBUG_DIRECTORY debugDir, DWORD size, DWORD base)
{
    DWORD cDebugFormats = size / sizeof(IMAGE_DEBUG_DIRECTORY);
    PSTR szDebugFormat;
    unsigned i;
    
    if ( cDebugFormats == 0 )
        return;
    
    printf(
    "Debug Formats in File\n"
    "  Type            Size     Address  FilePtr  Charactr TimeDate Version\n"
    "  --------------- -------- -------- -------- -------- -------- --------\n"
    );
    
    for ( i=0; i < cDebugFormats; i++ )
    {
        szDebugFormat = (debugDir->Type <= IMAGE_DEBUG_TYPE_OMAP_FROM_SRC )
                        ? SzDebugFormats[debugDir->Type] : "???";

        printf("  %-15s %08X %08X %08X %08X %08X %u.%02u\n",
            szDebugFormat, debugDir->SizeOfData, debugDir->AddressOfRawData,
            debugDir->PointerToRawData, debugDir->Characteristics,
            debugDir->TimeDateStamp, debugDir->MajorVersion,
            debugDir->MinorVersion);

		switch( debugDir->Type )
		{
        	case IMAGE_DEBUG_TYPE_COFF:
	            g_pCOFFHeader =
                (PIMAGE_COFF_SYMBOLS_HEADER)(base+ debugDir->PointerToRawData);
				break;

			case IMAGE_DEBUG_TYPE_MISC:
				g_pMiscDebugInfo =
				(PIMAGE_DEBUG_MISC)(base + debugDir->PointerToRawData);
				break;

			case IMAGE_DEBUG_TYPE_CODEVIEW:
				g_pCVHeader = (PDWORD)(base + debugDir->PointerToRawData);
				break;
		}

        debugDir++;
    }
}

/*----------------------------------------------------------------------------*/
//
// Other assorted stuff
//
/*----------------------------------------------------------------------------*/

//
// Do a hexadecimal dump of the raw data for all the sections.  You
// could just dump one section by adjusting the PIMAGE_SECTION_HEADER
// and cSections parameters
//
void DumpRawSectionData(PIMAGE_SECTION_HEADER section,
                        PVOID base,
                        unsigned cSections)
{
    unsigned i;
    char name[IMAGE_SIZEOF_SHORT_NAME + 1];

    printf("Section Hex Dumps\n");
    
    for ( i=1; i <= cSections; i++, section++ )
    {
        // Make a copy of the section name so that we can ensure that
        // it's null-terminated
        memcpy(name, section->Name, IMAGE_SIZEOF_SHORT_NAME);
        name[IMAGE_SIZEOF_SHORT_NAME] = 0;

        // Don't dump sections that don't exist in the file!
        if ( section->PointerToRawData == 0 )
            continue;
        
        printf( "section %02X (%s)  size: %08X  file offs: %08X\n",
                i, name, section->SizeOfRawData, section->PointerToRawData);

        HexDump( MakePtr(PBYTE, base, section->PointerToRawData),
                 section->SizeOfRawData );
        printf("\n");
    }
}

// Number of hex values displayed per line
#define HEX_DUMP_WIDTH 16

//
// Dump a region of memory in a hexadecimal format
//
void HexDump(PBYTE ptr, DWORD length)
{
    char buffer[256];
    PSTR buffPtr, buffPtr2;
    unsigned cOutput, i;
    DWORD bytesToGo=length;

    while ( bytesToGo  )
    {
        cOutput = bytesToGo >= HEX_DUMP_WIDTH ? HEX_DUMP_WIDTH : bytesToGo;

        buffPtr = buffer;
        buffPtr += sprintf(buffPtr, "%08X:  ", length-bytesToGo );
        buffPtr2 = buffPtr + (HEX_DUMP_WIDTH * 3) + 1;
        
        for ( i=0; i < HEX_DUMP_WIDTH; i++ )
        {
            BYTE value = *(ptr+i);

            if ( i >= cOutput )
            {
                // On last line.  Pad with spaces
                *buffPtr++ = ' ';
                *buffPtr++ = ' ';
                *buffPtr++ = ' ';
            }
            else
            {
                if ( value < 0x10 )
                {
                    *buffPtr++ = '0';
                    itoa( value, buffPtr++, 16);
                }
                else
                {
                    itoa( value, buffPtr, 16);
                    buffPtr+=2;
                }
 
                *buffPtr++ = ' ';
                *buffPtr2++ = isprint(value) ? value : '.';
            }
            
            // Put an extra space between the 1st and 2nd half of the bytes
            // on each line.
            if ( i == (HEX_DUMP_WIDTH/2)-1 )
                *buffPtr++ = ' ';
        }

        *buffPtr2 = 0;  // Null terminate it.
        puts(buffer);   // Can't use printf(), since there may be a '%'
                        // in the string.
        bytesToGo -= cOutput;
        ptr += HEX_DUMP_WIDTH;
    }
}


