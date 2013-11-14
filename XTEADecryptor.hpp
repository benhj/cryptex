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

#ifndef I_ENCRYPTOR_XTEA_DECRYPTOR_HPP__
#define I_ENCRYPTOR_XTEA_DECRYPTOR_HPP__

#include "IEncryptor.hpp"
#include <string>
#include <sstream>

#include <vector>

namespace cryptex
{

    long const BUFFER_SIZE = 1000;

    namespace detail
    {

        // the xtea encipher algorithm as found on wikipedia
        void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4])
        {
            unsigned int i;
            uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
            for (i=0; i < num_rounds; i++) {
                v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + key[(sum>>11) & 3]);
                sum -= delta;
                v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + key[sum & 3]);
            }
            v[0]=v0; v[1]=v1;
        }

        // helper code as found here:
        // http://codereview.stackexchange.com/questions/2050/codereview-tiny-encryption-algorithm-for-arbitrary-sized-data
        void convertBytesAndDecypher(unsigned int num_rounds, unsigned char * buffer, uint32_t const key[4])
        {
            uint32_t datablock[2];

            datablock[0] = (buffer[0] << 24) | (buffer[1] << 16)  | (buffer[2] << 8) | (buffer[3]);
            datablock[1] = (buffer[4] << 24) | (buffer[5] << 16)  | (buffer[6] << 8) | (buffer[7]);

            decipher(num_rounds, datablock, key);

            buffer[0] = static_cast<unsigned char>((datablock[0] >> 24) & 0xFF);
            buffer[1] = static_cast<unsigned char>((datablock[0] >> 16) & 0xFF);
            buffer[2] = static_cast<unsigned char>((datablock[0] >> 8) & 0xFF);
            buffer[3] = static_cast<unsigned char>((datablock[0]) & 0xFF);
            buffer[4] = static_cast<unsigned char>((datablock[1] >> 24) & 0xFF);
            buffer[5] = static_cast<unsigned char>((datablock[1] >> 16) & 0xFF);
            buffer[6] = static_cast<unsigned char>((datablock[1] >> 8) & 0xFF);
            buffer[7] = static_cast<unsigned char>((datablock[1]) & 0xFF);
        }

    }

    class XTEADecryptor : public IEncryptor
    {

      public:
        XTEADecryptor(std::string const &key, int const rounds)
            : IEncryptor(key)
            , m_keyIndex(0)
            , m_rounds(rounds)
            , m_origDataLength(0)
            , m_dataWrittenSoFar(0)
        {

        }

      private:

        // for storing each 8-byte block of data
        typedef std::vector<unsigned char> Bytes;
        mutable Bytes m_eightByteBlock;

        // for storing the 16 byte key used during the encryption process
        // the key is generated as a function of the string. A 16 byte key
        // which contains 4 uint32_t are therefore generated from 16 of
        // the string key characters
        typedef std::vector<uint32_t> TeaKey;

        // the number of rounds used by the XTEA process. This is usually
        // 32 or 64 or 128 etc.
        mutable TeaKey m_teaKey;

        // determines where in the string key the tea key data is derived from
        mutable std::string::size_type m_keyIndex;

        // the number of rounds used by the XTEA process. This is usually
        // 32 or 64 or 128 etc.
        int const m_rounds;

        // the length of the original unencrypted data. This is recovered from
        // the encrypted data
        mutable uint32_t m_origDataLength;

        // the buffer is written to the stream in BUFFER_SIZE bursts. This
        // variable basically accumulates the number of such bursts * BUFFER_SIZE
        mutable uint32_t m_dataWrittenSoFar;

        // a buffer that stores decrypted bytes that will be written to the
        // underlying output stream
        mutable Bytes m_mainDataFuffer;

        /**
         * @brief recovers the length proper of the encrypted data from the
         * first four bytes of the eight byte block
         */
        void recoverDataLength() const
        {
            unsigned char dat[4];
            dat[0] = m_eightByteBlock[0];
            dat[1] = m_eightByteBlock[1];
            dat[2] = m_eightByteBlock[2];
            dat[3] = m_eightByteBlock[3];
            uint32_t *recovered = reinterpret_cast<uint32_t*>(dat);
            m_origDataLength = *recovered;
        }

        /**
         * @brief copies the 8-byte block data in to the main data buffer
         */
        void add8ByteBlockToMainDataBuffer() const
        {
            Bytes::iterator it = m_eightByteBlock.begin();
            for (; it != m_eightByteBlock.end(); ++it) {
                m_mainDataFuffer.push_back(*it);
            }
        }

        /**
         * @brief decrypts the 8-byte blocks of data
         * @param byte the byte to add to an 8-byte block
         * @param key the key used to decrypt the data
         * @param out the stream that data is written to
         * @param lastByte indicates that the byte is the last byte to be encrypted
         * @note TEA works by encrypting in 8-byte blocks. The following algorithm
         * expects TEA-encrypted data with a size of multiples of 8. When the last byte
         * is encountered, the algorithm knows that the 8-byte block buffer (i.e. the
         * last block) specifies size information. This size is repeated twice since the
         * size value is represented as a uint32_t (i.e. 4 bytes). The size value
         * can therefore be recovered from either the first or second 4 bytes of the
         * 8-byte block. When the function finished is called, the writing process
         * uses this value to signify how many bytes should be written from the
         * main data buffer
         */
        void doCryptTransform(unsigned char byte, std::string const &key, std::ostream &out, bool lastByte) const
        {
            addByteToTheByteBlock(byte);
            if (thereAre8BytesInTheByteBlock()) {
                prepareTEAKey(key);
                detail::convertBytesAndDecypher(m_rounds, &m_eightByteBlock.front(), &m_teaKey.front());

                //
                // recover length of original data from first 4 bytes of last 8-byte block;
                // a uint32_t which represents the length of our data is of size 4 bytes
                //
                if (lastByte) {
                    recoverDataLength();
                }

                //
                // Store deciphered bytes in buffer
                //
                add8ByteBlockToMainDataBuffer();

                //
                // Write out a load of the buffer so that it doesn't get too big
                //
                checkAndWriteOutBufferWindow(out);

                m_eightByteBlock.clear();
            }
        }

        void checkAndWriteOutBufferWindow(std::ostream &out) const
        {
            if (m_mainDataFuffer.size() == BUFFER_SIZE + 24) {
                out.write(reinterpret_cast<char*>(&m_mainDataFuffer.front()), BUFFER_SIZE);
                Bytes tempBuffer;
                tempBuffer.assign(m_mainDataFuffer.begin() + BUFFER_SIZE, m_mainDataFuffer.end());
                m_mainDataFuffer.assign(tempBuffer.begin(), tempBuffer.end());
                m_dataWrittenSoFar += BUFFER_SIZE;
            }
        }

        void doFinish(std::string const &key, std::ostream &out) const
        {
            //
            // write out buffer up to the recovered data length
            //
            out.write(reinterpret_cast<char*>(&m_mainDataFuffer.front()), m_origDataLength - m_dataWrittenSoFar);
        }

        void addByteToTheByteBlock(unsigned char &byte) const
        {
            m_eightByteBlock.push_back(byte);
        }

        bool thereAre8BytesInTheByteBlock() const
        {
            return m_eightByteBlock.size() == 8;
        }

        void generateKey(std::string const &userKey, unsigned char keyDat[4]) const
        {
            for (int i = 0; i < 4; ++i) {
                checkKeyIndexAndResetIfTooBig(userKey);
                keyDat[i] = userKey[m_keyIndex];
                ++m_keyIndex;
            }
        }

        void prepareTEAKey(std::string const &key) const
        {
            unsigned char dat[4];
            m_teaKey.clear();
            generateKey(key, dat);
            uint32_t *k1 = reinterpret_cast<uint32_t*>(dat);
            m_teaKey.push_back(*k1);

            generateKey(key, dat);
            uint32_t *k2 = reinterpret_cast<uint32_t*>(dat);
            m_teaKey.push_back(*k2);

            generateKey(key, dat);
            uint32_t *k3 = reinterpret_cast<uint32_t*>(dat);
            m_teaKey.push_back(*k3);

            generateKey(key, dat);
            uint32_t *k4 = reinterpret_cast<uint32_t*>(dat);
            m_teaKey.push_back(*k4);
        }

        void checkKeyIndexAndResetIfTooBig(std::string const &key) const
        {
            if (m_keyIndex >= key.length()) {
                m_keyIndex = 0;
            }
        }

    };

}

#endif
