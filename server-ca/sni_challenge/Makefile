CFLAGS+=-fpic -I/usr/include/python2.7
LDFLAGS+=

targets=_sni_support.so sni_support_wrap.c sni_support.py sni_support.o sni_support_wrap.o

all: _sni_support.so

sni_support_wrap.c sni_support.py: sni_support.i
	swig -python $^

_sni_support.so: sni_support_wrap.o sni_support.o
	$(CC) -shared $^ -o $@

clean:
	rm -f $(targets) *.pyc
