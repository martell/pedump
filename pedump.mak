PROJ = PEDUMP

OBJS =  PEDUMP.OBJ \
        COMMON.OBJ \
        OBJDUMP.OBJ \
        EXEDUMP.OBJ \
        DBGDUMP.OBJ \
        LIBDUMP.OBJ \
		COFFSYMBOLTABLE.OBJ \
		ROMIMAGE.OBJ \
		SYMBOLTABLESUPPORT.OBJ \
		RESDUMP.OBJ

LIBS = USER32.LIB

CFLAGS = /nologo /W3 /DWIN32_LEAN_AND_MEAN
LFLAGS = /NOLOGO /FIXED /MERGE:.idata=.data /MERGE:.rdata=.text \
		 /SUBSYSTEM:console 

!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS) /YX /D_DEBUG /Zi /Fd"$(PROJ).PDB" /Fp"$(PROJ).PCH"
LFLAGS = $(LFLAGS) /DEBUG /DEBUGTYPE:CV
!else
CFLAGS = $(CFLAGS) /DNDEBUG /O1
LFLAGS = $(LFLAGS)
!endif

all: $(PROJ).EXE

.cpp.obj:
    CL $(CFLAGS) /c $<

$(PROJ).EXE: $(OBJS)
    echo >NUL @<<$(PROJ).CRF
$(LFLAGS) $(OBJS) $(LIBS)
<<
    link @$(PROJ).CRF

