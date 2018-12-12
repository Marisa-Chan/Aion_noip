.DEFAULT_GOAL := default

CC=i686-w64-mingw32-gcc
OPTIONS = -Os -s

LOPTIONS = -nostdlib -Wl,--exclude-libs,msvcrt.a -Wl,-entry=_DllMain@12
LIBS = -lpsapi -lkernel32 -luser32

OBJS = game_wrap.cpp \
       game_wrap.def

OUT = game.dll

default:
	$(CC) -shared $(OBJS) $(OPTIONS) $(LOPTIONS) $(LIBS) -o $(OUT)


