cryptex
=======

A simple encryption api for writing stream-like ciphers in C++
Requires boost headers

Idea and motivation
-------------------

The presented code stems from a conversation I had on stackoverflow regarding the implementation of an encrypted output stream

http://stackoverflow.com/questions/19679537/serialize-an-object-to-encrypted-stdfstream-c

The question got me thinking about sources and sinks, abstractions of things or 'devices' that can be read from and written to respectively. Using the boost api, these are easily modeled and can be further wrapped in streams. 

And so the encryption sink idea was born. 

Because the overall approach involves streams, even block ciphers can be made to appear like stream ciphers.

General howto
-------------

Used correctly, the api involves implementing the pure virtual functions found in IEncryptor. These functions are:

doCryptTransform(unsigned char byte, std::string const &key, std::ostream &out, bool const lastByte)

and 

doFinish(std::string const &key, std::ostream &out) 

Since in many block ciphers, blocks of data are encrypted in N byte blocks, there will probably be some left over data if (streamSize % blockSize > 0) which needs to be padded out to a full block during the encryption process. For this, the doFinish function is utilizied to 'finish up' the encyption process by doing whatever leftover operations are required (if indeed this is how the encryption algorithm works).

An implemention of the XTEA algorithm found here:

http://en.wikipedia.org/wiki/XTEA

is provided and some simple test code which demonstrates how the encryption sink can be applied is provided.

Compilation
-----------

The user will need to edit the Makefile and set the boost header path (on my machine, this is found at /usr/local/boost_1_53_0 but on yours it might be someplace else)

After which, just run make. Running the test code should be self-explanatory.



