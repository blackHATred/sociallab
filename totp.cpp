#include <iostream>
#include <stdexcept>
#include <cinttypes>
#include <cstring>
#include <cassert>
#include <cstdlib>

using namespace std;

void clearByteString(basic_string<uint8_t> * bstr)
{
    volatile uint8_t * bs = const_cast<volatile uint8_t *>(bstr->data());

    for (size_t i = 0; i < bstr->size(); ++i)
    {
        bs[i] = uint8_t(0);
    }
}

void swizzleByteStrings(basic_string<uint8_t> * target, basic_string<uint8_t> * source)
{
    clearByteString(target);
    target->assign(*source);
    clearByteString(source);
}

static char nibbleToLCHex(uint8_t nib)
{
    if (nib < 0xa)
    {
        return static_cast<char>(nib + '0');
    }
    else if (nib < 0x10)
    {
        return static_cast<char>((nib - 10) + 'a');
    }
    else
    {
        assert(0 && "not actually a nibble");
        return '\0';
    }
}

static uint8_t hexToNibble(char c)
{
    if (c >= '0' && c <= '9')
    {
        return static_cast<uint8_t>(c - '0');
    }
    else if (c >= 'A' && c <= 'F')
    {
        return static_cast<uint8_t>(c - 'A' + 10);
    }
    else if (c >= 'a' && c <= 'f')
    {
        return static_cast<uint8_t>(c - 'a' + 10);
    }
    else
    {
        assert(0 && "not actually a hex digit");
        return 0xff;
    }
}

std::string toHexString(const basic_string<uint8_t> & bstr)
{
    std::string ret;

    for (uint8_t b : bstr)
    {
        ret.push_back(nibbleToLCHex((b >> 4) & 0x0F));
        ret.push_back(nibbleToLCHex((b >> 0) & 0x0F));
    }

    return ret;
}

basic_string<uint8_t> fromHexStringSkipUnknown(const std::string & str)
{
    std::string hstr;
    for (char c : str)
    {
        if (
                (c >= '0' && c <= '9') ||
                (c >= 'A' && c <= 'F') ||
                (c >= 'a' && c <= 'f')
                )
        {
            hstr.push_back(c);
        }
        // ignore otherwise
    }

    if (hstr.size() % 2 != 0)
    {
        throw std::invalid_argument("hex string (unknown characters ignored) length not divisible by 2");
    }

    basic_string<uint8_t> ret;
    for (size_t i = 0; i < hstr.size(); i += 2)
    {
        uint8_t top = hexToNibble(hstr[i+0]);
        uint8_t btm = hexToNibble(hstr[i+1]);

        ret.push_back((top << 4) | btm);
    }
    return ret;
}

basic_string<uint8_t> u32beToByteString(uint32_t num)
{
    basic_string<uint8_t> ret;
    ret.push_back((num >> 24) & 0xFF);
    ret.push_back((num >> 16) & 0xFF);
    ret.push_back((num >>  8) & 0xFF);
    ret.push_back((num >>  0) & 0xFF);
    return ret;
}

basic_string<uint8_t> u64beToByteString(uint64_t num)
{
    basic_string<uint8_t> left  = u32beToByteString((num >> 32) & 0xFFFFFFFF);
    basic_string<uint8_t> right = u32beToByteString((num >>  0) & 0xFFFFFFFF);
    return left + right;
}

static basic_string<uint8_t> b32ChunkToBytes(const std::string & str)
{
    basic_string<uint8_t> ret;
    uint64_t whole = 0x00;
    size_t padcount = 0;
    size_t finalcount;

    if (str.length() != 8)
    {
        throw std::invalid_argument("incorrect length of base32 chunk");
    }

    size_t i;

    for (i = 0; i < 8; ++i)
    {
        char c = str[i];
        uint64_t bits;

        if (c == '=')
        {
            bits = 0;
            ++padcount;
        }
        else if (padcount > 0)
        {
            throw std::invalid_argument("padding character followed by non-padding character");
        }
        else if (c >= 'A' && c <= 'Z')
        {
            bits = static_cast<uint8_t>(c - 'A');
        }
        else if (c >= '2' && c <= '7')
        {
            bits = static_cast<uint8_t>(c - '2' + 26);
        }
        else
        {
            throw std::invalid_argument("not a base32 character: " + std::string(1, c));
        }

        // shift into the chunk
        whole |= (bits << ((7-i)*5));
    }

    switch (padcount)
    {
        case 0:
            finalcount = 5;
            break;
        case 1:
            finalcount = 4;
            break;
        case 3:
            finalcount = 3;
            break;
        case 4:
            finalcount = 2;
            break;
        case 6:
            finalcount = 1;
            break;
        default:
            throw std::invalid_argument("invalid number of padding characters");
    }

    for (i = 0; i < finalcount; ++i)
    {
        // shift out of the chunk
        ret.push_back(static_cast<uint8_t>((whole >> ((4-i)*8)) & 0xFF));
    }

    return ret;
}

static inline uint64_t u64(uint8_t n)
{
    return static_cast<uint64_t>(n);
}

static std::string bytesToB32Chunk(const basic_string<uint8_t> & bs)
{
    if (bs.empty() || bs.size() > 5)
    {
        throw std::invalid_argument("need a chunk of at least 1 and at most 5 bytes");
    }

    uint64_t whole = 0x00;
    size_t putchars = 2;
    std::string ret;

    // shift into the chunk
    whole |= (u64(bs[0]) << 32);
    if (bs.size() > 1)
    {
        whole |= (u64(bs[1]) << 24);
        putchars += 2;  // at least 4
    }
    if (bs.size() > 2)
    {
        whole |= (u64(bs[2]) << 16);
        ++putchars;  // at least 5
    }
    if (bs.size() > 3)
    {
        whole |= (u64(bs[3]) <<  8);
        putchars += 2;  // at least 7
    }
    if (bs.size() > 4)
    {
        whole |= u64(bs[4]);
        ++putchars;  // at least 8
    }

    size_t i;
    for (i = 0; i < putchars; ++i)
    {
        // shift out of the chunk

        uint8_t val = (whole >> ((7-i)*5)) & 0x1F;

        // map bits to base32

        if (val < 26)
        {
            ret.push_back(static_cast<char>(val + 'A'));
        }
        else
        {
            ret.push_back(static_cast<char>(val - 26 + '2'));
        }
    }

    // pad

    for (i = putchars; i < 8; ++i)
    {
        ret.push_back('=');
    }

    return ret;
}

class ByteStringDestructor
{
private:
    /** The byte string to clear. */
    basic_string<uint8_t> * m_bs;

public:
    ByteStringDestructor(basic_string<uint8_t> * bs) : m_bs(bs) {}
    ~ByteStringDestructor() { clearByteString(m_bs); }
};

basic_string<uint8_t> fromBase32(const std::string & b32str)
{
    if (b32str.size() % 8 != 0)
    {
        throw std::invalid_argument("base32 string length not divisible by 8");
    }

    basic_string<uint8_t> ret;

    for (size_t i = 0; i < b32str.size(); i += 8)
    {
        std::string sub(b32str, i, 8);
        basic_string<uint8_t> chk = b32ChunkToBytes(sub);
        ret.append(chk);
    }

    return ret;
}

basic_string<uint8_t> fromUnpaddedBase32(const std::string & b32str)
{
    std::string newstr = b32str;

    while (newstr.size() % 8 != 0)
    {
        newstr.push_back('=');
    }

    return fromBase32(newstr);
}

std::string toBase32(const basic_string<uint8_t> & bs)
{
    std::string ret;

    size_t i, j, len;
    for (j = 0; j < bs.size() / 5; ++j)
    {
        i = j * 5;
        basic_string<uint8_t> sub(bs, i, 5);
        std::string chk = bytesToB32Chunk(sub);
        ret.append(chk);
    }

    i = j * 5;
    len = bs.size() - i;
    if (len > 0)
    {
        // block of size < 5 remains
        basic_string<uint8_t> sub(bs, i, std::string::npos);
        std::string chk = bytesToB32Chunk(sub);
        ret.append(chk);
    }

    return ret;
}

static inline uint32_t lrot32(uint32_t num, uint8_t rotcount)
{
    return (num << rotcount) | (num >> (32 - rotcount));
}

basic_string<uint8_t> sha1_(const basic_string<uint8_t> & msg)
{
    const size_t size_bytes = msg.size();
    const uint64_t size_bits = size_bytes * 8;
    basic_string<uint8_t> bstr = msg;
    ByteStringDestructor asplode(&bstr);

    // the size of msg in bits is always even. adding the '1' bit will make
    // it odd and therefore incongruent to 448 modulo 512, so we can get
    // away with tacking on 0x80 and then the 0x00s.
    bstr.push_back(0x80);
    while (bstr.size() % (512/8) != (448/8))
    {
        bstr.push_back(0x00);
    }

    // append the size in bits (uint64be)
    bstr.append(u64beToByteString(size_bits));

    assert(bstr.size() % (512/8) == 0);

    // initialize the hash counters
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    // for each 64-byte chunk
    for (size_t i = 0; i < bstr.size()/64; ++i)
    {
        basic_string<uint8_t> chunk(bstr.begin() + i*64, bstr.begin() + (i+1)*64);
        ByteStringDestructor xplode(&chunk);

        uint32_t words[80];
        size_t j;

        // 0-15: the chunk as a sequence of 32-bit big-endian integers
        for (j = 0; j < 16; ++j)
        {
            words[j] =
                    (chunk[4*j + 0] << 24) |
                    (chunk[4*j + 1] << 16) |
                    (chunk[4*j + 2] <<  8) |
                    (chunk[4*j + 3] <<  0)
                    ;
        }

        // 16-79: derivatives of 0-15
        for (j = 16; j < 32; ++j)
        {
            // unoptimized
            words[j] = lrot32(words[j-3] ^ words[j-8] ^ words[j-14] ^ words[j-16], 1);
        }
        for (j = 32; j < 80; ++j)
        {
            // Max Locktyuchin's optimization (SIMD)
            words[j] = lrot32(words[j-6] ^ words[j-16] ^ words[j-28] ^ words[j-32], 2);
        }

        // initialize hash values for the round
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        // the loop
        for (j = 0; j < 80; ++j)
        {
            uint32_t f = 0, k = 0;

            if (j < 20)
            {
                f = (b & c) | ((~ b) & d);
                k = 0x5A827999;
            }
            else if (j < 40)
            {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (j < 60)
            {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else if (j < 80)
            {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            else
            {
                assert(0 && "how did I get here?");
            }

            uint32_t tmp = lrot32(a, 5) + f + e + k + words[j];
            e = d;
            d = c;
            c = lrot32(b, 30);
            b = a;
            a = tmp;
        }

        // add that to the result so far
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    // assemble the digest
    basic_string<uint8_t> first  = u32beToByteString(h0);
    ByteStringDestructor x1(&first);
    basic_string<uint8_t> second = u32beToByteString(h1);
    ByteStringDestructor x2(&second);
    basic_string<uint8_t> third  = u32beToByteString(h2);
    ByteStringDestructor x3(&third);
    basic_string<uint8_t> fourth = u32beToByteString(h3);
    ByteStringDestructor x4(&fourth);
    basic_string<uint8_t> fifth  = u32beToByteString(h4);
    ByteStringDestructor x5(&fifth);

    return first + second + third + fourth + fifth;
}

basic_string<uint8_t> hmacSha1(const basic_string<uint8_t> & key, const basic_string<uint8_t> & msg, size_t blockSize = 64);

basic_string<uint8_t> hmacSha1(const basic_string<uint8_t> & key, const basic_string<uint8_t> & msg, size_t blockSize)
{
    basic_string<uint8_t> realKey = key;
    ByteStringDestructor asplode(&realKey);

    if (realKey.size() > blockSize)
    {
        // resize by calculating hash
        basic_string<uint8_t> newRealKey = sha1_(realKey);
        swizzleByteStrings(&realKey, &newRealKey);
    }
    if (realKey.size() < blockSize)
    {
        // pad with zeroes
        realKey.resize(blockSize, 0x00);
    }

    // prepare the pad keys
    basic_string<uint8_t> innerPadKey = realKey;
    ByteStringDestructor xplodeI(&innerPadKey);
    basic_string<uint8_t> outerPadKey = realKey;
    ByteStringDestructor xplodeO(&outerPadKey);

    // transform the pad keys
    for (size_t i = 0; i < realKey.size(); ++i)
    {
        innerPadKey[i] = innerPadKey[i] ^ 0x36;
        outerPadKey[i] = outerPadKey[i] ^ 0x5c;
    }

    // sha1(outerPadKey + sha1(innerPadKey + msg))
    basic_string<uint8_t> innerMsg  = innerPadKey + msg;
    ByteStringDestructor xplodeIM(&innerMsg);
    basic_string<uint8_t> innerHash = sha1_(innerMsg);
    ByteStringDestructor xplodeIH(&innerHash);
    basic_string<uint8_t> outerMsg  = outerPadKey + innerHash;
    ByteStringDestructor xplodeOM(&outerMsg);

    return sha1_(outerMsg);
}

basic_string<uint8_t> hmacSha1_64(const basic_string<uint8_t> & key, const basic_string<uint8_t> & msg)
{
    return hmacSha1(key, msg, 64);
}

typedef basic_string<uint8_t> (*HmacFunc)(const basic_string<uint8_t> &, const basic_string<uint8_t> &);


uint32_t hotp(const basic_string<uint8_t> & key, uint64_t counter, size_t digitCount, HmacFunc hmacf)
{
    basic_string<uint8_t> msg = u64beToByteString(counter);
    ByteStringDestructor dmsg(&msg);

    basic_string<uint8_t> hmac = hmacf(key, msg);
    ByteStringDestructor dhmac(&hmac);

    uint32_t digits10 = 1;
    for (size_t i = 0; i < digitCount; ++i)
    {
        digits10 *= 10;
    }

    // fetch the offset (from the last nibble)
    uint8_t offset = hmac[hmac.size()-1] & 0x0F;

    // fetch the four bytes from the offset
    basic_string<uint8_t> fourWord = hmac.substr(offset, 4);
    ByteStringDestructor dfourWord(&fourWord);

    // turn them into a 32-bit integer
    uint32_t ret =
            (fourWord[0] << 24) |
            (fourWord[1] << 16) |
            (fourWord[2] <<  8) |
            (fourWord[3] <<  0)
    ;

    // snip off the MSB (to alleviate signed/unsigned troubles)
    // and calculate modulo digit count
    return (ret & 0x7fffffff) % digits10;
}

uint32_t totp(const basic_string<uint8_t> & key, uint64_t timeNow, uint64_t timeStart, uint64_t timeStep, size_t digitCount = 6, HmacFunc hmacf = hmacSha1_64)
{
    uint64_t timeValue = (timeNow - timeStart) / timeStep;
    return hotp(key, timeValue, digitCount, hmacf);
}
