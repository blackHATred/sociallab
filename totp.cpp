#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using std::uint8_t;
using std::uint32_t;
using std::int64_t;
using std::uint64_t;
using std::size_t;
using std::string;
using std::vector;

static uint32_t rotateLeft(uint32_t x, int i) {
    return ((0U + x) << i) | (x >> (32 - i));
}
static vector<uint8_t> toBytesBigEndian(uint64_t x) {
    vector<uint8_t> result(8);
    for (auto it = result.rbegin(); it != result.rend(); ++it, x >>= 8)
        *it = static_cast<uint8_t>(x);
    return result;
}

// Function prototypes
vector<uint8_t> decodeBase32(std::string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    BYTE char_array_4[4], char_array_3[3];
    vector<BYTE> ret;

    while (in_len-- && ( encoded_string[in_] != '=')) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i ==4) {
            for (i = 0; i <4; i++)
                char_array_4[i] = string("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                  "abcdefghijklmnopqrstuvwxyz"
                                  "0123456789+/").find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = i; j <4; j++)
            char_array_4[j] = 0;

        for (j = 0; j <4; j++)
            char_array_4[j] = string("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                     "abcdefghijklmnopqrstuvwxyz"
                                     "0123456789+/").find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
    }

    return ret;
}


/*---- Library functions ----*/
static vector<uint8_t> calcHmac(
        vector<uint8_t> key,
        const vector<uint8_t> &message,
        vector<uint8_t> (*hashFunc)(vector<uint8_t>),
        int blockSize) {

    if (blockSize < 1)
        throw std::domain_error("Invalid block size");

    if (key.size() > static_cast<unsigned int>(blockSize))
        key = hashFunc(key);
    while (key.size() < static_cast<unsigned int>(blockSize))
        key.push_back(0);

    vector<uint8_t> innerMsg;
    for (auto it = key.cbegin(); it != key.cend(); ++it)
        innerMsg.push_back(static_cast<uint8_t>(*it ^ 0x36));
    innerMsg.insert(innerMsg.end(), message.cbegin(), message.cend());
    vector<uint8_t> innerHash = hashFunc(std::move(innerMsg));

    vector<uint8_t> outerMsg;
    for (auto it = key.cbegin(); it != key.cend(); ++it)
        outerMsg.push_back(static_cast<uint8_t>(*it ^ 0x5C));
    outerMsg.insert(outerMsg.end(), innerHash.cbegin(), innerHash.cend());
    return hashFunc(std::move(outerMsg));
}
string calcHotp(
        vector<uint8_t> secretKey,
        const vector<uint8_t> &counter,
        int codeLen,
        vector<uint8_t> (*hashFunc)(vector<uint8_t>),
        int blockSize) {

    // Check argument, calculate HMAC
    if (!(1 <= codeLen && codeLen <= 9))
        throw std::domain_error("Invalid number of digits");
    vector<uint8_t> hash = calcHmac(std::move(secretKey), counter, hashFunc, blockSize);

    // Dynamically truncate the hash value
    int offset = hash.back() & 0xF;
    unsigned long val = 0;
    for (int i = 0; i < 4; i++)
        val |= static_cast<unsigned long>(hash.at(offset + i)) << ((3 - i) * 8);
    val &= 0x7FFFFFFFUL;

    // Extract and format base-10 digits
    unsigned long tenPow = 1;
    for (int i = 0; i < codeLen; i++)
        tenPow *= 10;
    std::ostringstream result;
    result << std::setw(codeLen) << std::setfill('0') << (val % tenPow);
    return result.str();
}
string calcTotp(
        vector<uint8_t> secretKey,
        int64_t epoch,
        int64_t timeStep,
        int64_t timestamp,
        int codeLen,
        vector<uint8_t> (*hashFunc)(vector<uint8_t>),
        int blockSize) {

    // Calculate counter and HOTP
    int64_t temp = timestamp - epoch;
    if (temp < 0)
        temp -= timeStep - 1;
    uint64_t timeCounter = static_cast<uint64_t>(temp / timeStep);
    vector<uint8_t> counter = toBytesBigEndian(timeCounter);
    return calcHotp(std::move(secretKey), counter, codeLen, hashFunc, blockSize);
}


vector<uint8_t> calcSha1Hash(vector<uint8_t> message) {
    vector<uint8_t> bitLenBytes = toBytesBigEndian(message.size() * UINT64_C(8));
    message.push_back(0x80);
    while ((message.size() + 8) % 64 != 0)
        message.push_back(0x00);
    message.insert(message.end(), bitLenBytes.cbegin(), bitLenBytes.cend());

    uint32_t state[] = {
            UINT32_C(0x67452301),
            UINT32_C(0xEFCDAB89),
            UINT32_C(0x98BADCFE),
            UINT32_C(0x10325476),
            UINT32_C(0xC3D2E1F0),
    };
    for (size_t i = 0; i < message.size(); i += 64) {
        vector<uint32_t> schedule(16, 0);
        for (size_t j = 0; j < schedule.size() * 4; j++)
            schedule.at(j / 4) |= static_cast<uint32_t>(message.at(i + j)) << ((3 - j % 4) * 8);
        for (size_t j = schedule.size(); j < 80; j++) {
            uint32_t temp = schedule.at(j - 3) ^ schedule.at(j - 8) ^ schedule.at(j - 14) ^ schedule.at(j - 16);
            schedule.push_back(rotateLeft(temp, 1));
        }
        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        for (size_t j = 0; j < schedule.size(); j++) {
            uint32_t f, rc;
            switch (j / 20) {
                case 0:  f = (b & c) | (~b & d);           rc = UINT32_C(0x5A827999);  break;
                case 1:  f = b ^ c ^ d;                    rc = UINT32_C(0x6ED9EBA1);  break;
                case 2:  f = (b & c) ^ (b & d) ^ (c & d);  rc = UINT32_C(0x8F1BBCDC);  break;
                case 3:  f = b ^ c ^ d;                    rc = UINT32_C(0xCA62C1D6);  break;
                default:  throw std::domain_error("Assertion error");
            }
            uint32_t temp = 0U + rotateLeft(a, 5) + f + e + schedule.at(j) + rc;
            e = d;
            d = c;
            c = rotateLeft(b, 30);
            b = a;
            a = temp;
        }
        state[0] = 0U + state[0] + a;
        state[1] = 0U + state[1] + b;
        state[2] = 0U + state[2] + c;
        state[3] = 0U + state[3] + d;
        state[4] = 0U + state[4] + e;
    }

    vector<uint8_t> result;
    for (uint32_t val : state) {
        for (int i = 3; i >= 0; i--)
            result.push_back(static_cast<uint8_t>(val >> (i * 8)));
    }
    return result;
}
