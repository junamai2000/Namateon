CFILES = namateon.c nxjson.c http_server.c http_parser.c

#lex.yy.c: lex.l
#	$(LEX) $^
#parser.tab.c: parser.y
#	$(YACC) -d -b parser $^

obj-m += namateonmod.o
namateonmod-objs := $(CFILES:.c=.o)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
