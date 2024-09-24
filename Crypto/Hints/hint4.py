from operator import mul
from operator import xor
from functools import reduce
from struct import unpack
def hash(d):
	j=unpack
	y=bytes
	e=mul
	w=bytearray
	n=xor
	i=reduce
	f=map
	l=b'\x3e\x68\x68\x69'
	q=w(b'\x0a'*4)
	r=len
	d=w(d)
	h=b'\x00\x0b\x01\x01\x00\x14\x2a\x2d'
	h=i(e,j(l,h))
	l=b'\x3e\x49'
	k=w(b'\xc0\xf4\xb0\xb4')
	c=h^(h&0x0)
	q=i(e,j(l,y(w(f(n,k,q)))))
	k=r(d)
	y,j=h^c,h
	while (y>>(c^3735928571))<k:
		j=(j^(((2**(4*1<<2)-1)*(y%(c^3736977135)>0))&((d[y>>(c^3735928571)]*q)^(0xface*(y>>(c^3735928571))))))&(2**(4*1<<2)-1)
		y+=(h^(h-0xf+0x2*7))
	return format(j, 'x')