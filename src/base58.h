// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


//
// Why base-58 instead of standard base-64 encoding?
// - Don't want 0OIl characters that look the same in some fonts and
//      could be used to create visually identical looking account numbers.
// - A string with non-alphanumeric characters is not as easily accepted as an account number.
// - E-mail usually won't line-break if there's no punctuation to break at.
// - Double-clicking selects the whole number as one word if it's all alphanumeric.
//
// This base-58 codec encodes a sequence of bytes, not just a big-endian number.
// The difference is that we preserve the exact number of leading 0 bytes.
// Each leading zero is represented by a leading 0-value base-58 digit ('1').
// The remaining bytes, starting from the first non-zero byte, are then interpreted
// as a big-endian binary number and converted into a big-endian base-58 number.
//
// Example:
// base-58 encoded:  "127"  ==  binary: 0x00 0x40
// "1" leading 0-byte --------------------^^   ^^
// "2" 1-valued base-58 digit ----> 1*58 + 6 = 64
// "7" 6-valued base-58 digit -------------^
//
#ifndef BITCOIN_BASE58_H
#define BITCOIN_BASE58_H

#include "bignum.h"
#include "chainparams.h"
#include "hash.h"
#include "key.h"
#include "script.h"
#include "uint256.h"

#include <string>
#include <vector>

#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// We convert in chunks of BASE58_CHUNK_DIGITS base-58 digits.
// BASE58_CHUNK_DIGITS is the maximum number of base-58 digits fitting into a BN_ULONG.
// BASE58_CHUNK_MOD is pow(58, BASE58_CHUNK_DIGITS)
enum {
    BASE58_CHUNK_DIGITS = (sizeof(BN_ULONG) == 8 ? 10 : 5),
    BASE58_CHUNK_MOD    = (sizeof(BN_ULONG) == 8 ? 0x5fa8624c7fba400ULL : 0x271f35a0ULL), // 58^10 : 58^5
};

// Encode a byte sequence as a base58-encoded string
inline std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    const unsigned char* p;

    // Convert bignum to std::string
    std::string str;
    // Expected size increase from base58 conversion is log(256)/log(58) approximately 1.36566
    // use 350/256 to be safe
    str.reserve(((pend - pbegin) * 350) / 256 + 1);

    // Leading zeros encoded as base58 zeros
    for (p = pbegin; p < pend && *p == 0; p++)
        str += pszBase58[0];
    ptrdiff_t nLeadingZeros = p - pbegin;

    // Convert big endian data to bignum
    CBigNum bn;
    BN_bin2bn(p, pend - p, &bn);

    BN_ULONG rem;
    while (1)
    {
        rem = BN_div_word(&bn, BASE58_CHUNK_MOD);
        if (rem == (BN_ULONG) -1)
            throw bignum_error("EncodeBase58 : BN_div_word failed");
        if (!bn)
            break;		// Not a full chunk
        for (int i = 0; i < BASE58_CHUNK_DIGITS; i++)
        {
            str += pszBase58[rem % 58];
            rem /= 58;
        }
    }
    while (rem != 0)
    {
        str += pszBase58[rem % 58];
        rem /= 58;
    }

    // Convert little endian std::string after leading zeros to big endian
    reverse(str.begin() + nLeadingZeros, str.end());
    return str;
}

// Encode a byte vector as a base58-encoded string
inline std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

// Decode a base58-encoded string psz into byte vector vchRet
// returns true if decoding is successful
inline bool DecodeBase58(const char* psz, std::vector<unsigned char>& vchRet)
{
    // use unsigned char as array index
    const unsigned char* p = (const unsigned char*)psz;
    CBigNum bn = 0;

    // map base58 digit to number, BAD, or SPACE
    enum RBASE58 {
        // 0 .. 57			// base58 digit of value 0 .. 57
        RBASE58_BAD   = -1,		// neither base58, nor white space
        RBASE58_SPACE = -2		// space, tab, newline, vtab, form feed, carriage return
    };
    static const signed char rgi8RBase58[256] =
        {-1,-1,-1,-1,-1,-1,-1,-1,-1,-2,-2,-2,-2,-2,-1,-1,
         -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
         -2,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
         -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
         -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
         22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
         -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
         47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
         -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
         -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
         -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
         -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
         -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
         -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
         -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
         -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1 };

    // The above initializer was calculated using:
    //    memset(rgi8RBase58, RBASE58_BAD, 256);
    //    rgi8RBase58[' ']  = RBASE58_SPACE;
    //    rgi8RBase58['\t'] = RBASE58_SPACE;
    //    rgi8RBase58['\n'] = RBASE58_SPACE;
    //    rgi8RBase58['\v'] = RBASE58_SPACE;
    //    rgi8RBase58['\f'] = RBASE58_SPACE;
    //    rgi8RBase58['\r'] = RBASE58_SPACE;
    //
    //    for (int i = 0; i < 58; i++)
    //        rgi8RBase58[(unsigned char)pszBase58[i]] = i;

    // Skip whitespace
    while (rgi8RBase58[*p] == RBASE58_SPACE)
        p++;

    // Count leading zeros
    int nLeadingZeros;
    for (nLeadingZeros = 0; *p == pszBase58[0]; p++)
        nLeadingZeros++;

    // Convert big endian string to bignum
    // We accumulate digits in acc and count them
    BN_ULONG acc = 0;
    int nDigits = 0;
    int v;
    while ((v = rgi8RBase58[*p]) >= 0)
    {
        acc *= 58;
        acc += v;
        nDigits++;
        if (nDigits == BASE58_CHUNK_DIGITS)
        {
            // push accumulated digits into bn
            bn *= BASE58_CHUNK_MOD;
            bn += acc;
            acc = 0;
            nDigits = 0;
        }
        p++;
    }
    // push remaining digits
    if (nDigits > 0)
    {
        BN_ULONG mul = 58;
        while (--nDigits > 0)
            mul *= 58;
        bn *= mul;
        bn += acc;
    }

    // Skip whitespace after base58 string
    while (rgi8RBase58[*p] == RBASE58_SPACE)
        p++;

    // Fail if there is junk at the end
    if (*p != '\0')
        return false;

    // Fill in leading zeros and make space for bn
    vchRet.assign(nLeadingZeros + BN_num_bytes(&bn), 0);

    // Fill big endian bn into the right place
    BN_bn2bin(&bn, &vchRet[nLeadingZeros]);

    return true;
}

// Decode a base58-encoded string str into byte vector vchRet
// returns true if decoding is successful
inline bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58(str.c_str(), vchRet);
}




// Encode a byte vector to a base58-encoded string, including checksum
inline std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

// Decode a base58-encoded string psz that includes a checksum, into byte vector vchRet
// returns true if decoding is successful
inline bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet))
        return false;
    if (vchRet.size() < 4)
    {
        vchRet.clear();
        return false;
    }
    uint256 hash = Hash(vchRet.begin(), vchRet.end()-4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0)
    {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size()-4);
    return true;
}

// Decode a base58-encoded string str that includes a checksum, into byte vector vchRet
// returns true if decoding is successful
inline bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58Check(str.c_str(), vchRet);
}





/** Base class for all base58-encoded data */
class CBase58Data
{
protected:
    // the version byte(s)
    std::vector<unsigned char> vchVersion;

    // the actually encoded data
    typedef std::vector<unsigned char, zero_after_free_allocator<unsigned char> > vector_uchar;
    vector_uchar vchData;

    CBase58Data()
    {
        vchVersion.clear();
        vchData.clear();
    }

    void SetData(const std::vector<unsigned char> &vchVersionIn, const void* pdata, size_t nSize)
    {
        vchVersion = vchVersionIn;
        vchData.resize(nSize);
        if (!vchData.empty())
            memcpy(&vchData[0], pdata, nSize);
    }

    void SetData(const std::vector<unsigned char> &vchVersionIn, const unsigned char *pbegin, const unsigned char *pend)
    {
        SetData(vchVersionIn, (void*)pbegin, pend - pbegin);
    }

public:
    bool SetString(const char* psz, unsigned int nVersionBytes = 1)
    {
        std::vector<unsigned char> vchTemp;
        DecodeBase58Check(psz, vchTemp);
        if (vchTemp.size() < nVersionBytes)
        {
            vchData.clear();
            vchVersion.clear();
            return false;
        }
        vchVersion.assign(vchTemp.begin(), vchTemp.begin() + nVersionBytes);
        vchData.resize(vchTemp.size() - nVersionBytes);
        if (!vchData.empty())
            memcpy(&vchData[0], &vchTemp[nVersionBytes], vchData.size());
        OPENSSL_cleanse(&vchTemp[0], vchData.size());
        return true;
    }

    bool SetString(const std::string& str)
    {
        return SetString(str.c_str());
    }

    std::string ToString() const
    {
        std::vector<unsigned char> vch = vchVersion;
        vch.insert(vch.end(), vchData.begin(), vchData.end());
        return EncodeBase58Check(vch);
    }

    int CompareTo(const CBase58Data& b58) const
    {
        if (vchVersion < b58.vchVersion) return -1;
        if (vchVersion > b58.vchVersion) return  1;
        if (vchData < b58.vchData)   return -1;
        if (vchData > b58.vchData)   return  1;
        return 0;
    }

    bool operator==(const CBase58Data& b58) const { return CompareTo(b58) == 0; }
    bool operator<=(const CBase58Data& b58) const { return CompareTo(b58) <= 0; }
    bool operator>=(const CBase58Data& b58) const { return CompareTo(b58) >= 0; }
    bool operator< (const CBase58Data& b58) const { return CompareTo(b58) <  0; }
    bool operator> (const CBase58Data& b58) const { return CompareTo(b58) >  0; }
};

/** base58-encoded Bitcoin addresses.
 * Public-key-hash-addresses have version 0 (or 111 testnet).
 * The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
 * Script-hash-addresses have version 5 (or 196 testnet).
 * The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
 */
class CBitcoinAddress;
class CBitcoinAddressVisitor : public boost::static_visitor<bool>
{
private:
    CBitcoinAddress *addr;
public:
    CBitcoinAddressVisitor(CBitcoinAddress *addrIn) : addr(addrIn) { }
    bool operator()(const CKeyID &id) const;
    bool operator()(const CScriptID &id) const;
    bool operator()(const CNoDestination &no) const;
};

class CBitcoinAddress : public CBase58Data
{
public:
    bool Set(const CKeyID &id) {
        SetData(Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS), &id, 20);
        return true;
    }

    bool Set(const CScriptID &id) {
        SetData(Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS), &id, 20);
        return true;
    }

    bool Set(const CTxDestination &dest)
    {
        return boost::apply_visitor(CBitcoinAddressVisitor(this), dest);
    }

    bool IsValid() const
    {
        bool fCorrectSize = vchData.size() == 20;
        bool fKnownVersion = vchVersion == Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS) ||
                             vchVersion == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        return fCorrectSize && fKnownVersion;
    }

    CBitcoinAddress()
    {
    }

    CBitcoinAddress(const CTxDestination &dest)
    {
        Set(dest);
    }

    CBitcoinAddress(const std::string& strAddress)
    {
        SetString(strAddress);
    }

    CBitcoinAddress(const char* pszAddress)
    {
        SetString(pszAddress);
    }

    CTxDestination Get() const {
        if (!IsValid())
            return CNoDestination();
        uint160 id;
        memcpy(&id, &vchData[0], 20);
        if (vchVersion == Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS))
            return CKeyID(id);
        else if (vchVersion == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS))
            return CScriptID(id);
        else
            return CNoDestination();
    }

    bool GetKeyID(CKeyID &keyID) const {
        if (!IsValid() || vchVersion != Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS))
            return false;
        uint160 id;
        memcpy(&id, &vchData[0], 20);
        keyID = CKeyID(id);
        return true;
    }

    bool IsScript() const {
        return IsValid() && vchVersion == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS);
    }
};

bool inline CBitcoinAddressVisitor::operator()(const CKeyID &id) const         { return addr->Set(id); }
bool inline CBitcoinAddressVisitor::operator()(const CScriptID &id) const      { return addr->Set(id); }
bool inline CBitcoinAddressVisitor::operator()(const CNoDestination &id) const { return false; }

/** A base58-encoded secret key */
class CBitcoinSecret : public CBase58Data
{
public:
    void SetKey(const CKey& vchSecret)
    {
        assert(vchSecret.IsValid());
        SetData(Params().Base58Prefix(CChainParams::SECRET_KEY), vchSecret.begin(), vchSecret.size());
        if (vchSecret.IsCompressed())
            vchData.push_back(1);
    }

    CKey GetKey()
    {
        CKey ret;
        ret.Set(&vchData[0], &vchData[32], vchData.size() > 32 && vchData[32] == 1);
        return ret;
    }

    bool IsValid() const
    {
        bool fExpectedFormat = vchData.size() == 32 || (vchData.size() == 33 && vchData[32] == 1);
        bool fCorrectVersion = vchVersion == Params().Base58Prefix(CChainParams::SECRET_KEY);
        return fExpectedFormat && fCorrectVersion;
    }

    bool SetString(const char* pszSecret)
    {
        return CBase58Data::SetString(pszSecret) && IsValid();
    }

    bool SetString(const std::string& strSecret)
    {
        return SetString(strSecret.c_str());
    }

    CBitcoinSecret(const CKey& vchSecret)
    {
        SetKey(vchSecret);
    }

    CBitcoinSecret()
    {
    }
};


template<typename K, int Size, CChainParams::Base58Type Type> class CBitcoinExtKeyBase : public CBase58Data
{
public:
    void SetKey(const K &key) {
        unsigned char vch[Size];
        key.Encode(vch);
        SetData(Params().Base58Prefix(Type), vch, vch+Size);
    }

    K GetKey() {
        K ret;
        ret.Decode(&vchData[0], &vchData[Size]);
        return ret;
    }

    CBitcoinExtKeyBase(const K &key) {
        SetKey(key);
    }

    CBitcoinExtKeyBase() {}
};

typedef CBitcoinExtKeyBase<CExtKey, 74, CChainParams::EXT_SECRET_KEY> CBitcoinExtKey;
typedef CBitcoinExtKeyBase<CExtPubKey, 74, CChainParams::EXT_PUBLIC_KEY> CBitcoinExtPubKey;

#endif // BITCOIN_BASE58_H
