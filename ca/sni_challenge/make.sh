#!/bin/bash
#Quick script to compile/load sni_support
#Will change to something more appropriate in the future

#Modify python path

swig -python sni_support.i
gcc -fpic -I/home/james/virtualenvs/chocolate/include/python2.7 -c sni_support_wrap.c sni_support.c
gcc -shared sni_support_wrap.o sni_support.o -o _sni_support.so 
