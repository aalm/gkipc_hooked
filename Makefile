# completely written w/o thinking about 64bit machines at all.
# i've tested some things w/success on 32bit x86 debian, ymmv.
# necessary fixes for 64bit machines go beyond s/Elf32/Elf64/,
# == not worth it. target is and will always remain 32bit.
#CC	=	gcc
CC	=	arm-goke-linux-uclibcgnueabi-gcc
#CC	=	arm-goke-linux-gnueabi-gcc
CFLAGS	+=	-Wall -Wextra

all:
	$(CC) $(CFLAGS) -o hw.so -fPIC hookwrap.c -shared -ldl
	$(CC) $(CFLAGS) -o test_target test_target.c

clean:
	rm -f *.so *.o test_target
