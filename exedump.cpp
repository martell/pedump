//==================================
// PEDUMP - Matt Pietrek 1997
// FILE: EXEDUMP.C
//==================================

#include <windows.h>
#include <stdio.h>
#include <time.h>
#pragma hdrstop
#include "common.h"
#include "symboltablesupport.h"
#include "COFFSymbolTable.h"
#include "resdump.h"
#include "extrnvar.h"

void DumpExeDebugDirectory(DWORD base, PIMAGE_NT_HEADERS pNTHeader)
{
    PIMAGE_DEBUG_DIRECTORY debugDir;
    PIMAGE_SECTION_HEADER header;
    DWORD va_debug_dir;
    DWORD size;
    
    va_debug_dir = GetImgDirEntryRVA(pNTHeader, IMAGE_DIRECTORY_ENTRY_DEBUG);

    if ( va_debug_dir == 0 )
        return;

    // If we found a .debug section, and the debug directory is at the
    // beginning of this section, it looks like a Borland file
    header = GetSectionHeader(".debug", pNTHeader);
    if ( header && (header->VirtualAddress == va_debug_dir) )
    {
        debugDir = (PIMAGE_DEBUG_DIRECTORY)(header->PointerToRawData+base);
        size = GetImgDirEntrySize(pNTHeader, IMAGE_DIRECTORY_ENTRY_DEBUG)
                * sizeof(IMAGE_DEBUG_DIRECTORY);
    }
    else    // Look for the debug directory
    {
        header = GetEnclosingSectionHeader( va_debug_dir, pNTHeader );
        if ( !header )
            return;

        size = GetImgDirEntrySize( pNTHeader, IMAGE_DIRECTORY_ENTRY_DEBUG );
    
        debugDir = MakePtr(PIMAGE_DEBUG_DIRECTORY, base,
                            header->PointerToRawData
							+ (va_debug_dir - header->VirtualAddress) );
    }

    DumpDebugDirectory( debugDir, size, base );
}


//
// Dump the imports table (the .idata section) of a PE file
//
void DumpImportsSection(DWORD base, PIMAGE_NT_HEADERS pNTHeader)
{
    PIMAGE_IMPORT_DESCRIPTOR importDesc;
    PIMAGE_SECTION_HEADER pSection;
    PIMAGE_THUNK_DATA thunk, thunkIAT=0;
    PIMAGE_IMPORT_BY_NAME pOrdinalName;
    DWORD importsStartRVA;
	PSTR pszTimeDate;

    // Look up where the imports section is (normally in the .idata section)
    // but not necessarily so.  Therefore, grab the RVA from the data dir.
    importsStartRVA = GetImgDirEntryRVA(pNTHeader,IMAGE_DIRECTORY_ENTRY_IMPORT);
    if ( !importsStartRVA )
        return;

    // Get the IMAGE_SECTION_HEADER that contains the imports.  This is
    // usually the .idata section, but doesn't have to be.
    pSection = GetEnclosingSectionHeader( importsStartRVA, pNTHeader );
    if ( !pSection )
        return;

    importDesc = (PIMAGE_IMPORT_DESCRIPTOR)
    						GetPtrFromRVA(importsStartRVA,pNTHeader,base);
	if ( !importDesc )
		return;
            
    printf("Imports Table:\n");
    
    while ( 1 )
    {
        // See if we've reached an empty IMAGE_IMPORT_DESCRIPTOR
        if ( (importDesc->TimeDateStamp==0 ) && (importDesc->Name==0) )
            break;
        
        printf("  %s\n", GetPtrFromRVA(importDesc->Name, pNTHeader, base) );

        printf("  OrigFirstThunk:  %08X (Unbound IAT)\n",
      			importDesc->Characteristics);

		pszTimeDate = ctime((time_t *)&importDesc->TimeDateStamp);
        printf("  TimeDateStamp:   %08X", importDesc->TimeDateStamp );
		printf( pszTimeDate ?  " -> %s" : "\n", pszTimeDate );

        printf("  ForwarderChain:  %08X\n", importDesc->ForwarderChain);
        printf("  First thunk RVA: %08X\n", importDesc->FirstThunk);
    
        thunk = (PIMAGE_THUNK_DATA)importDesc->Characteristics;
        thunkIAT = (PIMAGE_THUNK_DATA)importDesc->FirstThunk;

        if ( thunk == 0 )   // No Characteristics field?
        {
            // Yes! Gotta have a non-zero FirstThunk field then.
            thunk = thunkIAT;
            
            if ( thunk == 0 )   // No FirstThunk field?  Ooops!!!
                return;
        }
        
        // Adjust the pointer to point where the tables are in the
        // mem mapped file.
        thunk = (PIMAGE_THUNK_DATA)GetPtrFromRVA((DWORD)thunk, pNTHeader, base);
		if (!thunk )
			return;

        thunkIAT = (PIMAGE_THUNK_DATA)
        			GetPtrFromRVA((DWORD)thunkIAT, pNTHeader, base);
    
        printf("  Ordn  Name\n");
        
        while ( 1 ) // Loop forever (or until we break out)
        {
            if ( thunk->u1.AddressOfData == 0 )
                break;

            if ( thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
            {
                printf( "  %4u", IMAGE_ORDINAL(thunk->u1.Ordinal) );
            }
            else
            {
                pOrdinalName = thunk->u1.AddressOfData;
                pOrdinalName = (PIMAGE_IMPORT_BY_NAME)
                			GetPtrFromRVA((DWORD)pOrdinalName, pNTHeader, base);
                    
                printf("  %4u  %s", pOrdinalName->Hint, pOrdinalName->Name);
            }
            
			// If the user explicitly asked to see the IAT entries, or
			// if it looks like the image has been bound, append the address
            if ( fShowIATentries || importDesc->TimeDateStamp )
                printf( " (Bound to: %08X)", thunkIAT->u1.Function );

            printf( "\n" );

            thunk++;            // Advance to next thunk
            thunkIAT++;         // advance to next thunk
        }

        importDesc++;   // advance to next IMAGE_IMPORT_DESCRIPTOR
        printf("\n");
    }
}

//
// Dump the exports table (usually the .edata section) of a PE file
//
void DumpExportsSection(DWORD base, PIMAGE_NT_HEADERS pNTHeader)
{
    PIMAGE_EXPORT_DIRECTORY exportDir;
    PIMAGE_SECTION_HEADER header;
    INT delta; 
    PSTR filename;
    DWORD i;
    PDWORD functions;
    PWORD ordinals;
    PSTR *name;
    DWORD exportsStartRVA, exportsEndRVA;
    
    exportsStartRVA = GetImgDirEntryRVA(pNTHeader,IMAGE_DIRECTORY_ENTRY_EXPORT);
    exportsEndRVA = exportsStartRVA +
	   				GetImgDirEntrySize(pNTHeader, IMAGE_DIRECTORY_ENTRY_EXPORT);

    // Get the IMAGE_SECTION_HEADER that contains the exports.  This is
    // usually the .edata section, but doesn't have to be.
    header = GetEnclosingSectionHeader( exportsStartRVA, pNTHeader );
    if ( !header )
        return;

    delta = (INT)(header->VirtualAddress - header->PointerToRawData);
        
    exportDir = MakePtr(PIMAGE_EXPORT_DIRECTORY, base,
                         exportsStartRVA - delta);
        
    filename = (PSTR)(exportDir->Name - delta + base);
        
    printf("exports table:\n\n");
    printf("  Name:            %s\n", filename);
    printf("  Characteristics: %08X\n", exportDir->Characteristics);
    printf("  TimeDateStamp:   %08X -> %s",
    			exportDir->TimeDateStamp,
    			ctime((time_t *)&exportDir->TimeDateStamp) );
    printf("  Version:         %u.%02u\n", exportDir->MajorVersion,
            exportDir->MinorVersion);
    printf("  Ordinal base:    %08X\n", exportDir->Base);
    printf("  # of functions:  %08X\n", exportDir->NumberOfFunctions);
    printf("  # of Names:      %08X\n", exportDir->NumberOfNames);
    
    functions = (PDWORD)((DWORD)exportDir->AddressOfFunctions - delta + base);
    ordinals = (PWORD)((DWORD)exportDir->AddressOfNameOrdinals - delta + base);
    name = (PSTR *)((DWORD)exportDir->AddressOfNames - delta + base);

    printf("\n  Entry Pt  Ordn  Name\n");
    for ( i=0; i < exportDir->NumberOfFunctions; i++ )
    {
        DWORD entryPointRVA = functions[i];
        DWORD j;

        if ( entryPointRVA == 0 )   // Skip over gaps in exported function
            continue;               // ordinals (the entrypoint is 0 for
                                    // these functions).

        printf("  %08X  %4u", entryPointRVA, i + exportDir->Base );

        // See if this function has an associated name exported for it.
        for ( j=0; j < exportDir->NumberOfNames; j++ )
            if ( ordinals[j] == i )
                printf("  %s", name[j] - delta + base);

        // Is it a forwarder?  If so, the entry point RVA is inside the
        // .edata section, and is an RVA to the DllName.EntryPointName
        if ( (entryPointRVA >= exportsStartRVA)
             && (entryPointRVA <= exportsEndRVA) )
        {
            printf(" (forwarder -> %s)", entryPointRVA - delta + base );
        }
        
        printf("\n");
    }
}

void DumpRuntimeFunctions( DWORD base, PIMAGE_NT_HEADERS pNTHeader )
{
	DWORD rtFnRVA;

	rtFnRVA = GetImgDirEntryRVA( pNTHeader, IMAGE_DIRECTORY_ENTRY_EXCEPTION );
	if ( !rtFnRVA )
		return;

	DWORD cEntries =
		GetImgDirEntrySize( pNTHeader, IMAGE_DIRECTORY_ENTRY_EXCEPTION )
		/ sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY );
	if ( 0 == cEntries )
		return;

	PIMAGE_RUNTIME_FUNCTION_ENTRY pRTFn = (PIMAGE_RUNTIME_FUNCTION_ENTRY)
							GetPtrFromRVA( rtFnRVA, pNTHeader, base );

	if ( !pRTFn )
		return;

	printf( "Runtime Function Table (Exception handling)\n" );
    printf( "  Begin     End\n" );
    printf( "  --------  --------  --------\n" );

	for ( unsigned i = 0; i < cEntries; i++, pRTFn++ )
	{
        printf( "  %08X  %08X", pRTFn->BeginAddress, pRTFn->EndAddress );

		if ( g_pCOFFSymbolTable )
		{
			PCOFFSymbol pSymbol
				= g_pCOFFSymbolTable->GetNearestSymbolFromRVA(
										pRTFn->BeginAddress
										- pNTHeader->OptionalHeader.ImageBase,
										TRUE );
			if ( pSymbol )
				printf( "  %s", pSymbol->GetName() );

			delete pSymbol;
		}

		printf( "\n" );
	}
}

// The names of the available base relocations
char *SzRelocTypes[] = {
"ABSOLUTE","HIGH","LOW","HIGHLOW","HIGHADJ","MIPS_JMPADDR",
"SECTION","REL32" };

//
// Dump the base relocation table of a PE file
//
void DumpBaseRelocationsSection(DWORD base, PIMAGE_NT_HEADERS pNTHeader)
{
	DWORD dwBaseRelocRVA;
    PIMAGE_BASE_RELOCATION baseReloc;

	dwBaseRelocRVA =
		GetImgDirEntryRVA( pNTHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC );
    if ( !dwBaseRelocRVA )
        return;

    baseReloc = (PIMAGE_BASE_RELOCATION)
    				GetPtrFromRVA( dwBaseRelocRVA, pNTHeader, base );
	if ( !baseReloc )
		return;

    printf("base relocations:\n\n");

    while ( baseReloc->SizeOfBlock != 0 )
    {
        unsigned i,cEntries;
        PWORD pEntry;
        char *szRelocType;
        WORD relocType;

		// Sanity check to make sure the data looks OK.
		if ( 0 == baseReloc->VirtualAddress )
			break;
		if ( baseReloc->SizeOfBlock < sizeof(*baseReloc) )
			break;
		
        cEntries = (baseReloc->SizeOfBlock-sizeof(*baseReloc))/sizeof(WORD);
        pEntry = MakePtr( PWORD, baseReloc, sizeof(*baseReloc) );
        
        printf("Virtual Address: %08X  size: %08X\n",
                baseReloc->VirtualAddress, baseReloc->SizeOfBlock);
            
        for ( i=0; i < cEntries; i++ )
        {
            // Extract the top 4 bits of the relocation entry.  Turn those 4
            // bits into an appropriate descriptive string (szRelocType)
            relocType = (*pEntry & 0xF000) >> 12;
            szRelocType = relocType < 8 ? SzRelocTypes[relocType] : "unknown";
            
            printf("  %08X %s",
                    (*pEntry & 0x0FFF) + baseReloc->VirtualAddress,
                    szRelocType);

			if ( IMAGE_REL_BASED_HIGHADJ == relocType )
			{
				pEntry++;
				cEntries--;
				printf( " (%X)", *pEntry );
			}

			printf( "\n" );
            pEntry++;   // Advance to next relocation entry
        }
        
        baseReloc = MakePtr( PIMAGE_BASE_RELOCATION, baseReloc,
                             baseReloc->SizeOfBlock);
    }
}

//
// Dump out the new IMAGE_BOUND_IMPORT_DESCRIPTOR that NT 3.51 added
//
void DumpBoundImportDescriptors( DWORD base, PIMAGE_NT_HEADERS pNTHeader )
{
    DWORD bidRVA;   // Bound import descriptors RVA
    PIMAGE_BOUND_IMPORT_DESCRIPTOR pibid;

    bidRVA = GetImgDirEntryRVA(pNTHeader, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
    if ( !bidRVA )
        return;
    
    pibid = MakePtr( PIMAGE_BOUND_IMPORT_DESCRIPTOR, base, bidRVA );
    
    printf( "Bound import descriptors:\n\n" );
    printf( "  Module        TimeDate\n" );
    printf( "  ------------  --------\n" );
    
    while ( pibid->TimeDateStamp )
    {
        unsigned i;
        PIMAGE_BOUND_FORWARDER_REF pibfr;
        
        printf( "  %-12s  %08X -> %s",
        		base + bidRVA + pibid->OffsetModuleName,
                pibid->TimeDateStamp,
                ctime((time_t *)&pibid->TimeDateStamp) );
                            
        pibfr = MakePtr(PIMAGE_BOUND_FORWARDER_REF, pibid,
                            sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR));

        for ( i=0; i < pibid->NumberOfModuleForwarderRefs; i++ )
        {
            printf("    forwarder:  %-12s  %08X -> %s", 
                            base + bidRVA + pibfr->OffsetModuleName,
                            pibfr->TimeDateStamp,
                            ctime((time_t *)&pibfr->TimeDateStamp) );
            pibfr++;    // advance to next forwarder ref
                
            // Keep the outer loop pointer up to date too!
            pibid = MakePtr( PIMAGE_BOUND_IMPORT_DESCRIPTOR, pibid,
                             sizeof( IMAGE_BOUND_FORWARDER_REF ) );
        }

        pibid++;    // Advance to next pibid;
    }
}

//
// top level routine called from PEDUMP.C to dump the components of a PE file
//
void DumpExeFile( PIMAGE_DOS_HEADER dosHeader )
{
    PIMAGE_NT_HEADERS pNTHeader;
    DWORD base = (DWORD)dosHeader;
    
    pNTHeader = MakePtr( PIMAGE_NT_HEADERS, dosHeader,
                                dosHeader->e_lfanew );

    // First, verify that the e_lfanew field gave us a reasonable
    // pointer, then verify the PE signature.
#if 0
    __try
#endif
    {
        if ( pNTHeader->Signature != IMAGE_NT_SIGNATURE )
        {
            printf("Not a Portable Executable (PE) EXE\n");
            return;
        }
    }
#if 0
    __except( TRUE )    // Should only get here if pNTHeader (above) is bogus
    {
        printf( "invalid .EXE\n");
        return;
    }
#endif
    
    DumpHeader((PIMAGE_FILE_HEADER)&pNTHeader->FileHeader);
    printf("\n");

    DumpOptionalHeader((PIMAGE_OPTIONAL_HEADER)&pNTHeader->OptionalHeader);
    printf("\n");

    DumpSectionTable( IMAGE_FIRST_SECTION(pNTHeader), 
                        pNTHeader->FileHeader.NumberOfSections, TRUE);
    printf("\n");

    DumpExeDebugDirectory(base, pNTHeader);
    if ( pNTHeader->FileHeader.PointerToSymbolTable == 0 )
        g_pCOFFHeader = 0; // Doesn't really exist!
    printf("\n");

    DumpResourceSection(base, pNTHeader);
    printf("\n");

    DumpImportsSection(base, pNTHeader);
    printf("\n");
    
    if ( GetImgDirEntryRVA( pNTHeader, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) )
    {
        DumpBoundImportDescriptors( base, pNTHeader );
        printf( "\n" );
    }
    
    DumpExportsSection(base, pNTHeader);
    printf("\n");

	//=========================================================================
	//
	// If we have COFF symbols, create a symbol table now
	//
	//=========================================================================

	if ( g_pCOFFHeader )	// Did we see a COFF symbols header while looking
	{						// through the debug directory?
		g_pCOFFSymbolTable = new COFFSymbolTable(
				(PVOID)(base+ pNTHeader->FileHeader.PointerToSymbolTable),
				pNTHeader->FileHeader.NumberOfSymbols );
	}

	if ( fShowPDATA )
	{
		DumpRuntimeFunctions( base, pNTHeader );
		printf( "\n" );
	}

    if ( fShowRelocations )
    {
        DumpBaseRelocationsSection(base, pNTHeader);
        printf("\n");
    } 

	if ( fShowSymbolTable && g_pMiscDebugInfo )
	{
		DumpMiscDebugInfo( g_pMiscDebugInfo );
		printf( "\n" );
	}

	if ( fShowSymbolTable && g_pCVHeader )
	{
		DumpCVDebugInfo( g_pCVHeader );
		printf( "\n" );
	}

    if ( fShowSymbolTable && g_pCOFFHeader )
    {
        DumpCOFFHeader( g_pCOFFHeader );
        printf("\n");
    }
    
    if ( fShowLineNumbers && g_pCOFFHeader )
    {
        DumpLineNumbers( MakePtr(PIMAGE_LINENUMBER, g_pCOFFHeader,
                            g_pCOFFHeader->LvaToFirstLinenumber),
                            g_pCOFFHeader->NumberOfLinenumbers);
        printf("\n");
    }

    if ( fShowSymbolTable )
    {
        if ( pNTHeader->FileHeader.NumberOfSymbols 
            && pNTHeader->FileHeader.PointerToSymbolTable
			&& g_pCOFFSymbolTable )
        {
            DumpSymbolTable( g_pCOFFSymbolTable );
            printf("\n");
        }
    }
    
    if ( fShowRawSectionData )
    {
        DumpRawSectionData( (PIMAGE_SECTION_HEADER)(pNTHeader+1),
                            dosHeader,
                            pNTHeader->FileHeader.NumberOfSections);
    }

	if ( g_pCOFFSymbolTable )
		delete g_pCOFFSymbolTable;
}
