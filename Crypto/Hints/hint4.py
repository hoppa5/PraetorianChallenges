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
	l=b'\x3e\x68\x68\x69' # Define a little-endian format '>hhi'
	q=bytearray(b'\x0a' * 4) # Create a bytearray with four newline chars '\n\n\n\n'
	r=len
	d=bytearray(d) # Convert the input string or bytes to a bytearray
	h=b'\x00\x0b\x01\x01\x00\x14\x2a\x2d'
	h=reduce(mul, unpack(l,h)) # Unpack the bytesequence 'h' using the format '>hhi' and reduce it using multiplication 
	l=b'\x3e\x49' # Define a big-endian format
	k=bytearray(b'\xc0\xf4\xb0\xb4') 
	c=h^(h&0x0)
	q=reduce(mul, unpack(l, bytes(bytearray(map(xor, k, q))))) # XOR the elements of 'k' and 'q', then unpack the result using big-endian format '>I' and reduce it using multiplication
	k=len(d)
	y,j=h^c,h

	while (y >> (c ^ 3735928571)) < k:
		j = (j ^ (((65535) * (y % (c ^ 3736977135) > 0)) & ((d[y >> (c ^ 3735928571)] * q) ^ (0xface * (y >> (c ^ 3735928571)))))) & (65535)
		y += (h ^ (h - 0xf + 0x2 * 7))

	return format(j, 'x') # Return the final result as a hex string

def main():
	print(hash(b"test"))


if __name__ == "__main__":
	main()