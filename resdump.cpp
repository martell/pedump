//==================================
// PEDUMP - Matt Pietrek 1997
// FILE: RESDUMP.C
//==================================

#include <windows.h>
#include <stdio.h>
#include <time.h>
#pragma hdrstop
#include "common.h"
#include "extrnvar.h"
#include "resdump.h"

// Function prototype (necessary because two functions recurse)
void DumpResourceDirectory
(
    PIMAGE_RESOURCE_DIRECTORY resDir, DWORD resourceBase,
    DWORD level, DWORD resourceType
);

// The predefined resource types
char *SzResourceTypes[] = {
"???_0",
"CURSOR",
"BITMAP",
"ICON",
"MENU",
"DIALOG",
"STRING",
"FONTDIR",
"FONT",
"ACCELERATORS",
"RCDATA",
"MESSAGETABLE",
"GROUP_CURSOR",
"???_13",
"GROUP_ICON",
"???_15",
"VERSION",
"DLGINCLUDE",
"???_18",
"PLUGPLAY",
"VXD",
"ANICURSOR",
"ANIICON"
};

PIMAGE_RESOURCE_DIRECTORY_ENTRY pStrResEntries = 0;
PIMAGE_RESOURCE_DIRECTORY_ENTRY pDlgResEntries = 0;
DWORD cStrResEntries = 0;
DWORD cDlgResEntries = 0;

DWORD GetOffsetToDataFromResEntry( 	DWORD base,
									DWORD resourceBase,
									PIMAGE_RESOURCE_DIRECTORY_ENTRY pResEntry )
{
	// The IMAGE_RESOURCE_DIRECTORY_ENTRY is gonna point to a single
	// IMAGE_RESOURCE_DIRECTORY, which in turn will point to the
	// IMAGE_RESOURCE_DIRECTORY_ENTRY, which in turn will point
	// to the IMAGE_RESOURCE_DATA_ENTRY that we're really after.  In
	// other words, traverse down a level.

	PIMAGE_RESOURCE_DIRECTORY pStupidResDir;
	pStupidResDir = (PIMAGE_RESOURCE_DIRECTORY)
                    (resourceBase + pResEntry->OffsetToDirectory);

    PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry =
	    	(PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pStupidResDir + 1);// PTR MATH

	PIMAGE_RESOURCE_DATA_ENTRY pResDataEntry =
			(PIMAGE_RESOURCE_DATA_ENTRY)(resourceBase +
										 pResDirEntry->OffsetToData);

	return pResDataEntry->OffsetToData;
}

void DumpStringTable( 	DWORD base,
						PIMAGE_NT_HEADERS pNTHeader,
						DWORD resourceBase,
						PIMAGE_RESOURCE_DIRECTORY_ENTRY pStrResEntry,
						DWORD cStrResEntries )
{
	for ( unsigned i = 0; i < cStrResEntries; i++, pStrResEntry++ )
	{
		DWORD offsetToData
			= GetOffsetToDataFromResEntry( base, resourceBase, pStrResEntry );
			
 		PWORD pStrEntry = (PWORD)GetPtrFromRVA(	offsetToData,
												pNTHeader, base );
		if ( !pStrEntry)
			break;
		
		unsigned id = (pStrResEntry->Name - 1) << 4;

		for ( unsigned j = 0; j < 16; j++ )
		{
			WORD len = *pStrEntry++;
			if ( len )
			{
				printf( "%-5u: ", id + j );

				for ( unsigned k = 0; k < min(len, (WORD)64); k++ )
				{
					char * s;
					char szBuff[20];
					char c = (char)pStrEntry[k];
					switch( c )
					{
						case '\t': s = "\\t"; break;
						case '\r': s = "\\r"; break;
						case '\n': s = "\\n"; break;
						default:
							wsprintf( szBuff, "%c", isprint(c) ? c : '.' );
							s=szBuff;
							break;
					}

					printf( s );
				}

				printf( "\n" );
			}

			pStrEntry += len;
		}
	}
}

void DumpDialogs( 	DWORD base,
					PIMAGE_NT_HEADERS pNTHeader,
					DWORD resourceBase,
					PIMAGE_RESOURCE_DIRECTORY_ENTRY pDlgResEntry,
					DWORD cDlgResEntries )
{
	for ( unsigned i = 0; i < cDlgResEntries; i++, pDlgResEntry++ )
	{
		DWORD offsetToData
			= GetOffsetToDataFromResEntry( base, resourceBase, pDlgResEntry );
			
 		PDWORD pDlgStyle = (PDWORD)GetPtrFromRVA(	offsetToData,
													pNTHeader, base );
		if ( !pDlgStyle )
			break;
													
		printf( "  ====================\n" );
		if ( HIWORD(*pDlgStyle) != 0xFFFF )
		{
			//	A regular DLGTEMPLATE
			DLGTEMPLATE * pDlgTemplate = ( DLGTEMPLATE * )pDlgStyle;

			printf( "  style: %08X\n", pDlgTemplate->style );			
			printf( "  extended style: %08X\n", pDlgTemplate->dwExtendedStyle );			

			printf( "  controls: %u\n", pDlgTemplate->cdit );
			printf( "  (%u,%u) - (%u,%u)\n",
						pDlgTemplate->x, pDlgTemplate->y,
						pDlgTemplate->x + pDlgTemplate->cx,
						pDlgTemplate->y + pDlgTemplate->cy );
			PWORD pMenu = (PWORD)(pDlgTemplate + 1);	// ptr math!

			//
			// First comes the menu
			//
			if ( *pMenu )
			{
				if ( 0xFFFF == *pMenu )
				{
					pMenu++;
					printf( "  ordinal menu: %u\n", *pMenu );
				}
				else
				{
					printf( "  menu: " );
					while ( *pMenu )
						printf( "%c", LOBYTE(*pMenu++) );				

					pMenu++;
					printf( "\n" );
				}
			}
			else
				pMenu++;	// Advance past the menu name

			//
			// Next comes the class
			//			
			PWORD pClass = pMenu;
						
			if ( *pClass )
			{
				if ( 0xFFFF == *pClass )
				{
					pClass++;
					printf( "  ordinal class: %u\n", *pClass );
				}
				else
				{
					printf( "  class: " );
					while ( *pClass )
					{
						printf( "%c", LOBYTE(*pClass++) );				
					}		
					pClass++;
					printf( "\n" );
				}
			}
			else
				pClass++;	// Advance past the class name
			
			//
			// Finally comes the title
			//

			PWORD pTitle = pClass;
			if ( *pTitle )
			{
				printf( "  title: " );

				while ( *pTitle )
					printf( "%c", LOBYTE(*pTitle++) );
					
				pTitle++;
			}
			else
				pTitle++;	// Advance past the Title name

			printf( "\n" );

			PWORD pFont = pTitle;
						
			if ( pDlgTemplate->style & DS_SETFONT )
			{
				printf( "  Font: %u point ",  *pFont++ );
				while ( *pFont )
					printf( "%c", LOBYTE(*pFont++) );

				pFont++;
				printf( "\n" );
			}
	        else
    	        pFont = pTitle; 

			// DLGITEMPLATE starts on a 4 byte boundary
			LPDLGITEMTEMPLATE pDlgItemTemplate = (LPDLGITEMTEMPLATE)pFont;
			
			for ( unsigned i=0; i < pDlgTemplate->cdit; i++ )
			{
				// Control item header....
				pDlgItemTemplate = (DLGITEMTEMPLATE *)
									(((DWORD)pDlgItemTemplate+3) & ~3);
				
				printf( "    style: %08X\n", pDlgItemTemplate->style );			
				printf( "    extended style: %08X\n",
						pDlgItemTemplate->dwExtendedStyle );			

				printf( "    (%u,%u) - (%u,%u)\n",
							pDlgItemTemplate->x, pDlgItemTemplate->y,
							pDlgItemTemplate->x + pDlgItemTemplate->cx,
							pDlgItemTemplate->y + pDlgItemTemplate->cy );
				printf( "    id: %u\n", pDlgItemTemplate->id );
				
				//
				// Next comes the control's class name or ID
				//			
				PWORD pClass = (PWORD)(pDlgItemTemplate + 1);
				if ( *pClass )
				{							
					if ( 0xFFFF == *pClass )
					{
						pClass++;
						printf( "    ordinal class: %u", *pClass++ );
					}
					else
					{
						printf( "    class: " );
						while ( *pClass )
							printf( "%c", LOBYTE(*pClass++) );

						pClass++;
						printf( "\n" );
					}
				}
				else
					pClass++;
					
				printf( "\n" );			

				//
				// next comes the title
				//

				PWORD pTitle = pClass;
				
				if ( *pTitle )
				{
					printf( "    title: " );
					if ( 0xFFFF == *pTitle )
					{
						pTitle++;
						printf( "%u\n", *pTitle++ );
					}
					else
					{
						while ( *pTitle )
							printf( "%c", LOBYTE(*pTitle++) );
						pTitle++;
						printf( "\n" );
					}
				}
				else	
					pTitle++;	// Advance past the Title name

				printf( "\n" );
				
				PBYTE pCreationData = (PBYTE)(((DWORD)pTitle + 1) & 0xFFFFFFFE);
				
				if ( *pCreationData )
					pCreationData += *pCreationData;
				else
					pCreationData++;

				pDlgItemTemplate = (DLGITEMTEMPLATE *)pCreationData;	
				
				printf( "\n" );
			}
			
			printf( "\n" );
		}
		else
		{
			// A DLGTEMPLATEEX		
		}
		
		printf( "\n" );
	}
}

// Get an ASCII string representing a resource type
void GetResourceTypeName(DWORD type, PSTR buffer, UINT cBytes)
{
    if ( type <= (WORD)RT_ANIICON )
        strncpy(buffer, SzResourceTypes[type], cBytes);
    else
        sprintf(buffer, "%X", type);
}

//
// If a resource entry has a string name (rather than an ID), go find
// the string and convert it from unicode to ascii.
//
void GetResourceNameFromId
(
    DWORD id, DWORD resourceBase, PSTR buffer, UINT cBytes
)
{
    PIMAGE_RESOURCE_DIR_STRING_U prdsu;

    // If it's a regular ID, just format it.
    if ( !(id & IMAGE_RESOURCE_NAME_IS_STRING) )
    {
        sprintf(buffer, "%X", id);
        return;
    }
    
    id &= 0x7FFFFFFF;
    prdsu = (PIMAGE_RESOURCE_DIR_STRING_U)(resourceBase + id);

    // prdsu->Length is the number of unicode characters
    WideCharToMultiByte(CP_ACP, 0, prdsu->NameString, prdsu->Length,
                        buffer, cBytes, 0, 0);
    buffer[ min(cBytes-1,prdsu->Length) ] = 0;  // Null terminate it!!!
}

//
// Dump the information about one resource directory entry.  If the
// entry is for a subdirectory, call the directory dumping routine
// instead of printing information in this routine.
//
void DumpResourceEntry
(
    PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry,
    DWORD resourceBase,
    DWORD level
)
{
    UINT i;
    char nameBuffer[128];
    PIMAGE_RESOURCE_DATA_ENTRY pResDataEntry;
    
    if ( resDirEntry->OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY )
    {
        DumpResourceDirectory( (PIMAGE_RESOURCE_DIRECTORY)
            ((resDirEntry->OffsetToData & 0x7FFFFFFF) + resourceBase),
            resourceBase, level, resDirEntry->Name);
        return;
    }

    // Spit out the spacing for the level indentation
    for ( i=0; i < level; i++ )
        printf("    ");

    if ( resDirEntry->Name & IMAGE_RESOURCE_NAME_IS_STRING )
    {
        GetResourceNameFromId(resDirEntry->Name, resourceBase, nameBuffer,
                              sizeof(nameBuffer));
        printf("Name: %s  DataEntryOffs: %08X\n",
            nameBuffer, resDirEntry->OffsetToData);
    }
    else
    {
        printf("ID: %08X  DataEntryOffs: %08X\n",
                resDirEntry->Name, resDirEntry->OffsetToData);
    }
    
    // the resDirEntry->OffsetToData is a pointer to an
    // IMAGE_RESOURCE_DATA_ENTRY.  Go dump out that information.  First,
    // spit out the proper indentation
    for ( i=0; i < level; i++ )
        printf("    ");
    
    pResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)
                    (resourceBase + resDirEntry->OffsetToData);
    printf("DataRVA: %05X  DataSize: %05X  CodePage: %X\n",
            pResDataEntry->OffsetToData, pResDataEntry->Size,
            pResDataEntry->CodePage);
}

//
// Dump the information about one resource directory.
//
void DumpResourceDirectory
(
    PIMAGE_RESOURCE_DIRECTORY resDir,
    DWORD resourceBase,
    DWORD level,
    DWORD resourceType
)
{
    PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry;
    char szType[64];
    UINT i;

    // Level 1 resources are the resource types
    if ( level == 1 )
    {
		printf( "    ---------------------------------------------------"
	            "-----------\n" );

		if ( resourceType & IMAGE_RESOURCE_NAME_IS_STRING )
		{
			GetResourceNameFromId( resourceType, resourceBase,
									szType, sizeof(szType) );
		}
		else
		{
	        GetResourceTypeName( resourceType, szType, sizeof(szType) );
		}
	}
    else    // All other levels, just print out the regular id or name
    {
        GetResourceNameFromId( resourceType, resourceBase, szType,
                               sizeof(szType) );
    }
	    
    // Spit out the spacing for the level indentation
    for ( i=0; i < level; i++ )
        printf("    ");

    printf(
        "ResDir (%s) Entries:%02X (Named:%02X, ID:%02X) TimeDate:%08X",
        szType, resDir->NumberOfNamedEntries+ resDir->NumberOfIdEntries,
        resDir->NumberOfNamedEntries, resDir->NumberOfIdEntries,
        resDir->TimeDateStamp );
        
	if ( resDir->MajorVersion || resDir->MinorVersion )
		printf( " Vers:%u.%02u", resDir->MajorVersion, resDir->MinorVersion );
	if ( resDir->Characteristics)
		printf( " Char:%08X", resDir->Characteristics );
	printf( "\n" );

	//
	// The "directory entries" immediately follow the directory in memory
	//
    resDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resDir+1);

	// If it's a stringtable, save off info for future use
	if ( level == 1 && (resourceType == (WORD)RT_STRING))
	{
		pStrResEntries = resDirEntry;
		cStrResEntries = resDir->NumberOfIdEntries;
	}

	// If it's a stringtable, save off info for future use
	if ( level == 1 && (resourceType == (WORD)RT_DIALOG))
	{
		pDlgResEntries = resDirEntry;
		cDlgResEntries = resDir->NumberOfIdEntries;
	}
	    
    for ( i=0; i < resDir->NumberOfNamedEntries; i++, resDirEntry++ )
        DumpResourceEntry(resDirEntry, resourceBase, level+1);

    for ( i=0; i < resDir->NumberOfIdEntries; i++, resDirEntry++ )
        DumpResourceEntry(resDirEntry, resourceBase, level+1);
}

//
// Top level routine called to dump out the entire resource hierarchy
//
void DumpResourceSection(DWORD base, PIMAGE_NT_HEADERS pNTHeader)
{
	DWORD resourcesRVA;
    PIMAGE_RESOURCE_DIRECTORY resDir;

	resourcesRVA = GetImgDirEntryRVA(pNTHeader, IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if ( !resourcesRVA )
		return;

    resDir = (PIMAGE_RESOURCE_DIRECTORY)
    		GetPtrFromRVA( resourcesRVA, pNTHeader, base );

	if ( !resDir )
		return;
		
    printf("Resources (RVA: %X)\n", resourcesRVA );

    DumpResourceDirectory(resDir, (DWORD)resDir, 0, 0);

	printf( "\n" );

	if ( !fShowResources )
		return;
		
	if ( cStrResEntries )
	{
		printf( "String Table\n" );

		DumpStringTable( 	base, pNTHeader, (DWORD)resDir,
							pStrResEntries, cStrResEntries );
		printf( "\n" );
	}

	if ( cDlgResEntries )
	{
		printf( "Dialogs\n" );

		DumpDialogs( 	base, pNTHeader, (DWORD)resDir,
						pDlgResEntries, cDlgResEntries );
		printf( "\n" );
	}
}
