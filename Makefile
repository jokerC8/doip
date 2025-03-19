target := doip_server

src := doip_entity.c \
	   doip_stream.c \
	   doip_utils.c  \
	   doip_main.c

obj := $(patsubst %.c, %.o, $(src))

CC := clang

CFLAGS += -g -O0 -Wall -fPIC

LDFLAGS += -lev

$(target):$(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o:%.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY:clean

clean:
	@rm -rf $(obj) $(target)
