/*
 * Copyright (C) 2015 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "CBC.h"
#include "Crypto.h"
#include <string.h>

CBCCommon::CBCCommon()
    : blockCipher(0), posn(16)
{
}

CBCCommon::~CBCCommon()
{
    clean(iv);
    clean(temp);
}

size_t CBCCommon::keySize() const
{
    return blockCipher->keySize();
}

size_t CBCCommon::ivSize() const
{
    return 16;
}

bool CBCCommon::setKey(const uint8_t *key, size_t len)
{
    // Verify the cipher's block size, just in case.
    if (blockCipher->blockSize() != 16)
        return false;

    // Set the key on the underlying block cipher.
    return blockCipher->setKey(key, len);
}

bool CBCCommon::setIV(const uint8_t *iv, size_t len)
{
    if (len != 16)
        return false;
    memcpy(this->iv, iv, 16);
    posn = 16;
    return true;
}

void CBCCommon::encrypt(uint8_t *output, const uint8_t *input, size_t len)
{
    uint8_t posn;
    while (len >= 16)
    {
        for (posn = 0; posn < 16; ++posn)
            iv[posn] ^= *input++;
        blockCipher->encryptBlock(iv, iv);
        for (posn = 0; posn < 16; ++posn)
            *output++ = iv[posn];
        len -= 16;
    }
}

void CBCCommon::decrypt(uint8_t *output, const uint8_t *input, size_t len)
{
    uint8_t posn;
    while (len >= 16)
    {
        blockCipher->decryptBlock(temp, input);
        for (posn = 0; posn < 16; ++posn)
        {
            uint8_t in = *input++;
            *output++ = temp[posn] ^ iv[posn];
            iv[posn] = in;
        }
        len -= 16;
    }
}

void CBCCommon::clear()
{
    blockCipher->clear();
    clean(iv);
    clean(temp);
    posn = 16;
}
