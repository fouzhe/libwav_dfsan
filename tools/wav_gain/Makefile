CC = clang
OBJECTS = ../../libwav.c wav_gain.c ../../io-func.o
LIBS =
CFLAGS = -g -Wall -Wextra -O0 -fsanitize=dataflow
rule = -fsanitize-blacklist=../../dfsan_abilist.txt
BINDIR = $(DESTDIR)/usr/bin
NAME = wav_gain

wav_gain: $(OBJECTS) lib
	$(CC) $(CFLAGS) $(rule) -o $(NAME) $(OBJECTS) $(LIBS)

clean:
	rm $(NAME)

lib:
	$(CC) $(CFLAGS) -fPIC -c ../../io-func.c -o ../../io-func.o