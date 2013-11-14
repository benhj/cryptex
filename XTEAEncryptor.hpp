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

#ifndef I_ENCRYPTOR_XTEA_ENCRYPTOR_HPP__
#define I_ENCRYPTOR_XTEA_ENCRYPTOR_HPP__

#include "IEncryptor.hpp"
#include <string>
#include <sstream>
#include <vector>

namespace cryptex
{

    namespace detail
    {

        // the xtea encipher algorithm as found on wikipedia
        void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4])
        {
            unsigned int i;
            uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
            for (i=0; i < num_rounds; i++) {
                v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + key[sum & 3]);
                sum += delta;
                v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + key[(sum>>11) & 3]);
            }
            v[0]=v0; v[1]=v1;
        }

        // helper code found here:
        // http://codereview.stackexchange.com/questions/2050/codereview-tiny-encryption-algorithm-for-arbitrary-sized-data
        void convertBytesAndEncipher(unsigned int num_rounds, unsigned char * buffer, uint32_t const key[4])
        {
            uint32_t datablock[2];

            datablock[0] = (buffer[0] << 24) | (buffer[1] << 16)  | (buffer[2] << 8) | (buffer[3]);
            datablock[1] = (buffer[4] << 24) | (buffer[5] << 16)  | (buffer[6] << 8) | (buffer[7]);

            encipher(num_rounds, datablock, key);

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

    class XTEAEncryptor : public IEncryptor
    {

      public:
        XTEAEncryptor(std::string const &key, int const rounds)
            : IEncryptor(key)
            , m_keyIndex(0)
            , m_rounds(rounds)
            , m_origDataLength(0)
        {

        }

      private:

        // for storing an 8-byte block of data
        typedef std::vector<unsigned char> Bytes;
        mutable Bytes m_eightByteBlock;

        // for storing the 16 byte key used during the encryption process
        // the key is generated as a function of the string. A 16 byte key
        // which contains 4 uint32_t are therefore generated from 16 of
        // the string key characters
        typedef std::vector<uint32_t> TeaKey;
        mutable TeaKey m_teaKey;

        // determines where in the string key the tea key data is derived from
        mutable std::string::size_type m_keyIndex;

        // the number of rounds used by the XTEA process. This is usually
        // 32 or 64 or 128 etc.
        int const m_rounds;

        // the length of the unencrypted data which is encoded in the final
        // 8-byte block of the ciphertext
        mutable uint32_t m_origDataLength;

        /**
         * @brief adds a byte to an 8-byte block and encrypts the 8-byte block
         * when full
         * @param byte the byte to add to an 8-byte block
         * @param key the key that the 8-byte block will be encrypted with
         * @param out the output stream that the encrypted data will be written to
         * @param not used
         */
        void doCryptTransform(unsigned char byte, std::string const &key, std::ostream &out, bool) const
        {
            addByteToTheByteBlock(byte);
            if (thereAre8BytesInTheByteBlock()) {
                prepareTEAKey(key);
                detail::convertBytesAndEncipher(m_rounds, &m_eightByteBlock.front(), &m_teaKey.front());
                out.write(reinterpret_cast<char*>(&m_eightByteBlock.front()), 8);
                m_eightByteBlock.clear();
                m_origDataLength += 8;
            }
        }

        /**
         * @brief pads out any left over bytes with extra bytes to make it up to
         * 8 bytes. In the context of TEA, this is important since the encryption
         * (and decryption process) operates on 8-byte blocks
         * @param key the key used to encrypt with
         * @param out where data is written to
         */
        void padOutLeftOverBytesTo8ByteBlock(std::string const &key, std::ostream &out) const
        {
            if (m_eightByteBlock.size() > 0) {
                m_origDataLength += m_eightByteBlock.size();

                for (int i = 0; i < (8 - m_eightByteBlock.size()); ++i) {
                    unsigned char extra = 0;
                    uint32_t val = extra;
                    addByteToTheByteBlock(extra);
                }
                prepareTEAKey(key);
                detail::convertBytesAndEncipher(m_rounds, &m_eightByteBlock.front(), &m_teaKey.front());
                out.write(reinterpret_cast<char*>(&m_eightByteBlock.front()), 8);
            }
            m_eightByteBlock.clear();
        }

        /**
         * @brief writes out the last 8 byte block with two copies of a uint32_t
         * (each of size 4 bytes) which specifies the length of the data being encrypted
         * We have two copies since the encryption process encrypts in 8-byte blocks
         * @param key the key used to encrypt with
         * @param out where data is written to
         */
        void writeLast8ByteLengthDataBlock(std::string const &key, std::ostream &out) const
        {
            unsigned char lenData[4];
            lenData[0] = m_origDataLength;
            lenData[1] = m_origDataLength >> 8;
            lenData[2] = m_origDataLength >> 16;
            lenData[3] = m_origDataLength >> 24;
            int c = 0;
            for (int i = 0; i < 8; ++i) {
                if(c == 4) {
                    c = 0;
                }
                unsigned char extra = lenData[c];
                addByteToTheByteBlock(extra);
                ++c;
            }
            prepareTEAKey(key);
            detail::convertBytesAndEncipher(m_rounds, &m_eightByteBlock.front(), &m_teaKey.front());
            out.write(reinterpret_cast<char*>(&m_eightByteBlock.front()), 8);
        }

        /**
         * @brief finished the encrypion process encrypting any left-over bytes
         * that couldn't be fitted in to an 8-byte block
         * @param key the key that each 8-byte block is encrypted with
         * @param out where the data is writeen to
         */
        void doFinish(std::string const &key, std::ostream &out) const
        {

            //
            // Pad out remaining bytes to 8 bytes. Note this is just junk and
            // can be anything since it won't be used during decryption process
            //
            padOutLeftOverBytesTo8ByteBlock(key, out);

            //
            // Set the last 8 byte block to specify original data length. The data
            // length is a 4 byte block (a uint32_t) and since the block is 8 bytes
            // we store it twice
            //
            writeLast8ByteLengthDataBlock(key, out);

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
