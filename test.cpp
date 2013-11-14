/* The MIT License (MIT)

Copyright (c) <2013> <Ben H.D. Jones>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.*/

#include "EncryptionSink.hpp"
#include "XTEAEncryptor.hpp"
#include "XTEADecryptor.hpp"

#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/make_shared.hpp>

#include <fstream>
#include <iostream>
#include <sstream>

using namespace cryptex;


unsigned long getStreamSize(std::ifstream &inFile)
{
    inFile.seekg (0, inFile.end);
    unsigned long length = inFile.tellg();
    inFile.seekg (0, inFile.beg);
    return length;
}


void encrypt(char const *fin, char const *fout, std::string const &key)
{

    // (i) Create the input and output streams. Note, these don't have
    // to be file streams
    std::ifstream inFile(fin, std::ios::in | std::ios::binary);
    std::ofstream testOutput(fout, std::ios::out | std::ios::binary);

    // (ii) Set up the encryption algorithm that we wish to use
    EncryptionSink::SharedEncryptor enc = boost::make_shared<XTEAEncryptor>(key, 64);
    
    // (iii) Create the sink device that we write to and make a stream out of it
    EncryptionSink sink(testOutput, getStreamSize(inFile), enc);
    boost::iostreams::stream<EncryptionSink> cipherStream(sink);
    
    // (iv) Copy the input stream to the cipher stream. This encrypts the data
    boost::iostreams::copy(inFile, cipherStream);
}

void decrypt(char const *fin, char const *fout, std::string const &key)
{

    // (i) Create the input and output streams. Note, these don't have
    // to be file streams
    std::ifstream inFile(fin, std::ios::in | std::ios::binary);
    std::ofstream testOutput(fout, std::ios::out | std::ios::binary);

    // (ii) Set up the encryption algorithm that we wish to use
    EncryptionSink::SharedEncryptor enc = boost::make_shared<XTEADecryptor>(key, 64);

    // (iii) Create the sink device that we write to and make a stream out of it
    EncryptionSink sink(testOutput, getStreamSize(inFile), enc);
    boost::iostreams::stream<EncryptionSink> cipherStream(sink);

    // (iv) Copy the input stream to the cipher stream. This encrypts the data
    boost::iostreams::copy(inFile, cipherStream);
}

int main(int argc, char **argv)
{

    if(argc < 5) {
        std::cout<<"Too few arguments"<<std::endl;
        return 1;
    }

    std::string str(argv[1]);

    if(str=="e") {
        encrypt(argv[2], argv[3], argv[4]);
    } else if(str=="d") {
        decrypt(argv[2], argv[3], argv[4]);
    }
    return 0;
}
