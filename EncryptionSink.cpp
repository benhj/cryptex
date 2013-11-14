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
#include <iostream>
#include <sstream>

namespace cryptex
{

    EncryptionSink::EncryptionSink(std::ostream &underlyingStream,
                                   unsigned long const sourceLength,
                                   SharedEncryptor const& enc)
        : m_underlyingStream(underlyingStream)
        , m_sourceLength(sourceLength)
        , m_pos(0)
        , m_enc(enc)
    {}

    std::streamsize
    EncryptionSink::write(char_type const * const buf, std::streamsize const n) const
    {
        //
        // write out bytes taking care to signify when we have written all bytes
        // In some encryption algorithms (e.g. TEA), the last n bytes specify
        // the original length of the data. During decryption, when we hit the
        // last byte we can extract this length data from the last n bytes;
        // n is determined by the type of algorithm. In TEA, the last 8 bytes
        // store length information (twice since the length is stored as a uint32)
        //
        for (unsigned long i = 0; i < static_cast<unsigned long>(n) ; ++i) {
            m_enc->encrypt(static_cast<unsigned char>(buf[i]),  m_underlyingStream, (m_pos == m_sourceLength-1));
            ++m_pos;
        }

        //
        // write out any 'left over bytes' / required padding. How this occurs is
        // algorithm dependent; the implementation of finish may in fact be empty.
        // In TEA, it pads up to 8 bytes when bytesWritten % 8 > 0. We then write
        // an extra 8 bytes indicating bytesWritten. During decryption
        // bytesWritten is decoded and used to indicate where we can stop writing
        // (i.e. pad and length bytes can be ignored).
        //
        if ((m_pos-1) == m_sourceLength-1) {
            m_enc->finish(m_underlyingStream);
        }
        return n;
    }

    EncryptionSink::~EncryptionSink()
    {
    }

}
