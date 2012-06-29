CFLAGS+=-fpic -I/usr/include/python2.7
LDFLAGS+=

targets=sni_support.so sni_support_wrap.c sni_support.py

all: sni_support.so

sni_support_wrap.c sni_support.py: sni_support.i
	swig -python $^

sni_support.so: sni_support_wrap.o sni_support.o
	$(CC) -shared $^ -o $@

clean:
	rm -f $(targets)
