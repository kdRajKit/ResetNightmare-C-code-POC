CC      = x86_64-w64-mingw32-gcc
TARGET  = resetnightmare_rajkitpoc.exe
SOURCES = asn.c asn_format.c crypto.c kerberos.c kpasswd.c directory.c logon.c resetnightmare_rajkitpoc.c
LIBS    = -lws2_32 -lwldap32 -lsecur32 -lnetapi32 -lcryptdll -lntdll -ladvapi32
WARNINGS = -Wall -Wextra -Werror -Wunused-function -Wconversion -Wsign-conversion -Wduplicated-cond -Wduplicated-branches -Wlogical-op
CFLAGS  = -std=c11 -O2 -flto $(WARNINGS)
LDFLAGS = -Wl,--gc-sections -s

$(TARGET): $(SOURCES) resetnightmare.h Makefile
	$(CC) $(CFLAGS) -ffunction-sections -fdata-sections $(SOURCES) -o $@ $(LDFLAGS) $(LIBS)

analyze:
	$(CC) -std=c11 -O0 -fanalyzer $(WARNINGS) $(SOURCES) -o /tmp/$(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: analyze clean
