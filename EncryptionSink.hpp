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

#ifndef ENCRYPTION_SINK_HPP__
#define ENCRYPTION_SINK_HPP__

#include "IEncryptor.hpp"

#include <boost/shared_ptr.hpp>

#include <boost/iostreams/categories.hpp>  // sink_tag
#include <iosfwd>                          // streamsize
#include <string>

namespace cryptex
{

    class EncryptionSink
    {

      public:
        typedef boost::shared_ptr<IEncryptor> SharedEncryptor;
        typedef char                          char_type;
        typedef boost::iostreams::sink_tag    category;

        /**
         * @param underlyingStream where the data is actually written
         * @param sourceLength the size of the stream that will be copied from
         * @param enc implements an encryption algorithm (see IEncryptor)
         * @note we could pass in a path rather than a stream and construct the
         * underlying stream internally. But doing it this way affords the
         * flexibility of using any ostream type e.g. ofstream, ostringstream,
         * cout etc.
         */
        EncryptionSink(std::ostream &underlyingStream, unsigned long const sourceLength, SharedEncryptor const& enc);

        /**
         * @param buf the data to be written
         * @param n number of bytes to write
         * @return the number of bytes written
         */
        std::streamsize write(char_type const * const buf, std::streamsize const n) const;
        ~EncryptionSink();

      private:

        EncryptionSink(); // no impl required

        std::ostream &m_underlyingStream;
        unsigned long const m_sourceLength;
        mutable unsigned long m_pos;
        SharedEncryptor m_enc;
    };

}

#endif // ENCRYPTION_SINK_HPP__
