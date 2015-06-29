all:	pedump

CPPFLAGS = -fpermissive -Wno-write-strings -Wno-format

LDFLAGS = -lstdc++

CPPS = coffsymboltable.cpp common.cpp dbgdump.cpp exedump.cpp libdump.cpp objdump.cpp pedump.cpp resdump.cpp romimage.cpp symboltablesupport.cpp
OBJS = $(CPPS:.cpp=.o)

clean:
	rm -f *.o

install:
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install -m 755 pedump $(DESTDIR)$(PREFIX)/bin

pedump:	$(OBJS)
	g++ -o pedump $(OBJS) $(LDFLAGS)

