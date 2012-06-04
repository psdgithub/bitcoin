// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UINT256_H
#define BITCOIN_UINT256_H

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

#include "myendian.h"
#include "serialize.h"

typedef long long  int64;
typedef unsigned long long  uint64;


inline int Testuint256AdHoc(std::vector<std::string> vArg);



/** Base class without constructors for uint256 and uint160.
 * This makes the compiler let u use it in a union.
 */
template<unsigned int BITS>
class base_uint
{
protected:
    /** Internally, we use a big-endian array of native-endian 32-bit unsigned integers
     */
    enum { WIDTH=BITS/32 };
    uint32_t pn[WIDTH];
public:

    bool operator!() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (pn[i] != 0)
                return false;
        return true;
    }

    const base_uint operator~() const
    {
        base_uint ret;
        for (int i = 0; i < WIDTH; i++)
            ret.pn[i] = ~pn[i];
        return ret;
    }

    const base_uint operator-() const
    {
        base_uint ret;
        for (int i = 0; i < WIDTH; i++)
            ret.pn[i] = ~pn[i];
        ++ret;
        return ret;
    }


    base_uint& operator=(uint64 b)
    {
        Set64(b, 0, true);
        return *this;
    }

    base_uint& operator^=(const base_uint& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] ^= b.pn[i];
        return *this;
    }

    base_uint& operator&=(const base_uint& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] &= b.pn[i];
        return *this;
    }

    base_uint& operator|=(const base_uint& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] |= b.pn[i];
        return *this;
    }

    base_uint& operator^=(uint64 b)
    {
        pn[WIDTH-1] ^= b & 0xffffffff;
        pn[WIDTH-2] ^= b >> 32;
        return *this;
    }

    base_uint& operator|=(uint64 b)
    {
        pn[WIDTH-1] |= b & 0xffffffff;
        pn[WIDTH-2] |= b >> 32;
        return *this;
    }

    base_uint& operator<<=(unsigned int shift)
    {
        if (shift >= BITS)
        {
            memset(&pn[0], 0, sizeof(pn));
            return *this;
        }
        if (!shift)
            return *this;

        div_t q = div(shift, 32);
        int i;
        if (q.rem)
        {
            int rrem = 32 - q.rem, j;
            i = 0;
            for (j = q.quot; j < WIDTH-1; ++i, ++j)
                pn[i] = ((pn[j] << q.rem) & 0xffffffff) | (pn[j + 1] >> rrem);
            pn[i++] = (pn[j] << q.rem) & 0xffffffff;
        }
        else
            memmove(&pn[0], &pn[q.quot], sizeof(*pn) * (i = WIDTH - q.quot));
        for ( ; i < WIDTH; ++i)
            pn[i] = 0;
        return *this;
    }

    base_uint& operator>>=(unsigned int shift)
    {
        if (shift >= BITS)
        {
            memset(&pn[0], 0, sizeof(pn));
            return *this;
        }
        if (!shift)
            return *this;

        div_t q = div(shift, 32);
        int i;
        if (q.rem)
        {
            int rrem = 32 - q.rem, j;
            i = WIDTH-1;
            for (j = i - q.quot; j > 0; --i, --j)
                pn[i] = (pn[j] >> q.rem) | ((pn[j - 1] << rrem) & 0xffffffff);
            pn[i--] = pn[j] >> q.rem;
        }
        else
        {
            memmove(&pn[q.quot], &pn[0], sizeof(*pn) * (WIDTH - q.quot));
            i = q.quot - 1;
        }
        for ( ; i >= 0; --i)
            pn[i] = 0;
        return *this;
    }

    base_uint& operator+=(const base_uint& b)
    {
        uint64 carry = 0;
        for (int i = WIDTH-1; i >= 0; --i)
        {
            uint64 n = carry + pn[i] + b.pn[i];
            pn[i] = n & 0xffffffff;
            carry = n >> 32;
        }
        return *this;
    }

    base_uint& operator-=(const base_uint& b)
    {
        *this += -b;
        return *this;
    }

    base_uint& operator+=(uint64 b64)
    {
        base_uint b;
        b = b64;
        *this += b;
        return *this;
    }

    base_uint& operator-=(uint64 b64)
    {
        base_uint b;
        b = b64;
        *this += -b;
        return *this;
    }


    base_uint& operator++()
    {
        // prefix operator
        int i = WIDTH-1;
        while (++pn[i] == 0 && i >= 0)
            --i;
        return *this;
    }

    const base_uint operator++(int)
    {
        // postfix operator
        const base_uint ret = *this;
        ++(*this);
        return ret;
    }

    base_uint& operator--()
    {
        // prefix operator
        int i = WIDTH-1;
        while (--pn[i] == -1 && i >= 0)
            --i;
        return *this;
    }

    const base_uint operator--(int)
    {
        // postfix operator
        const base_uint ret = *this;
        --(*this);
        return ret;
    }


    friend inline bool operator<(const base_uint& a, const base_uint& b)
    {
        for (int i = 0; i < WIDTH; ++i)
        {
            if (a.pn[i] < b.pn[i])
                return true;
            else if (a.pn[i] > b.pn[i])
                return false;
        }
        return false;
    }

    friend inline bool operator<=(const base_uint& a, const base_uint& b)
    {
        for (int i = 0; i < WIDTH; ++i)
        {
            if (a.pn[i] < b.pn[i])
                return true;
            else if (a.pn[i] > b.pn[i])
                return false;
        }
        return true;
    }

    friend inline bool operator>(const base_uint& a, const base_uint& b)
    {
        for (int i = 0; i < WIDTH; ++i)
        {
            if (a.pn[i] > b.pn[i])
                return true;
            else if (a.pn[i] < b.pn[i])
                return false;
        }
        return false;
    }

    friend inline bool operator>=(const base_uint& a, const base_uint& b)
    {
        for (int i = 0; i < WIDTH; ++i)
        {
            if (a.pn[i] > b.pn[i])
                return true;
            else if (a.pn[i] < b.pn[i])
                return false;
        }
        return true;
    }

    friend inline bool operator==(const base_uint& a, const base_uint& b)
    {
        for (int i = 0; i < base_uint::WIDTH; i++)
            if (a.pn[i] != b.pn[i])
                return false;
        return true;
    }

    friend inline bool operator==(const base_uint& a, uint64 b)
    {
        if (a.pn[WIDTH-1] != (b & 0xffffffff))
            return false;
        if (a.pn[WIDTH-2] != b >> 32)
            return false;
        for (int i = 0; i < WIDTH-2; ++i)
            if (a.pn[i] != 0)
                return false;
        return true;
    }

    friend inline bool operator!=(const base_uint& a, const base_uint& b)
    {
        return (!(a == b));
    }

    friend inline bool operator!=(const base_uint& a, uint64 b)
    {
        return (!(a == b));
    }



    std::string GetHex() const
    {
        char psz[sizeof(pn)*2 + 1];
        for (unsigned int i = 0; i < WIDTH; ++i)
            sprintf(psz + i*8, "%08lx", (unsigned long)pn[i]);
        return std::string(psz, psz + sizeof(pn)*2);
    }

    void SetHex(const char* psz)
    {
        // skip leading spaces
        while (isspace(*psz))
            psz++;

        // skip 0x
        if (psz[0] == '0' && tolower(psz[1]) == 'x')
            psz += 2;

        // hex string to uint
        static unsigned char phexdigit[256] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0 };
        const unsigned char*pc = (const unsigned char*)psz;
        while (phexdigit[*pc] || *pc == '0')
            ++pc;
        for (int j = WIDTH-1; j >= 0; --j)
        {
            uint32_t n = 0;
            for (int i = 0; i < 32; i += 4)
            {
                if (pc <= (const unsigned char*)psz)
                    break;
                n |= phexdigit[*(--pc)] << i;
            }
            pn[j] = n;
        }
    }

    void SetHex(const std::string& str)
    {
        SetHex(str.c_str());
    }

    std::string ToString() const
    {
        return (GetHex());
    }

    unsigned int size()
    {
        return sizeof(pn);
    }

    uint64 Get64(int n=0) const
    {
        n = WIDTH-1 - (2*n);
        return pn[n] | (uint64)pn[n-1] << 32;
    }

    void Set64(int64 b, int n=0, bool clear=false)
    {
        if (clear)
            for (int i = 0; i < WIDTH; ++i)
                pn[i] = 0;
        n = WIDTH-1 - (2*n);
        pn[n  ] = b & 0xffffffff;
        pn[n-1] = b >> 32;
    }

    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        return sizeof(pn);
    }

    template<typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        for (int i = WIDTH-1; i >= 0; --i)
            ::Serialize(s, pn[i], nType, nVersion);
    }

    template<typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion)
    {
        for (int i = WIDTH-1; i >= 0; --i)
            ::Unserialize(s, pn[i], nType, nVersion);
    }


    friend class uint160;
    friend class uint256;
    friend inline int Testuint256AdHoc(std::vector<std::string> vArg);
};

typedef base_uint<160> base_uint160;
typedef base_uint<256> base_uint256;



//
// uint160 and uint256 could be implemented as templates, but to keep
// compile errors and debugging cleaner, they're copy and pasted.
//



//////////////////////////////////////////////////////////////////////////////
//
// uint160
//

/** 160-bit unsigned integer */
class uint160 : public base_uint160
{
public:
    typedef base_uint160 basetype;

    uint160()
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = 0;
    }

    uint160(const basetype& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
    }

    uint160& operator=(const basetype& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
        return *this;
    }

    uint160(uint64 b)
    {
        Set64(b, 0, true);
    }

    explicit uint160(const std::string& str)
    {
        SetHex(str);
    }

    explicit uint160(const std::vector<unsigned char>& vch)
    {
        if (vch.size() == sizeof(pn))
        {
            int j;
            for (int i = 0; i < WIDTH; ++i)
            {
                j = (WIDTH-1 - i) * 4;
                pn[i] = vch[j]
                     | (vch[j+1] <<  8)
                     | (vch[j+2] << 16)
                     | (vch[j+3] << 24);
            }
        }
        else
            *this = 0;
    }
};

inline bool operator==(const uint160& a, uint64 b)                           { return (base_uint160)a == b; }
inline bool operator!=(const uint160& a, uint64 b)                           { return (base_uint160)a != b; }
inline const uint160 operator<<(const base_uint160& a, unsigned int shift)   { return uint160(a) <<= shift; }
inline const uint160 operator>>(const base_uint160& a, unsigned int shift)   { return uint160(a) >>= shift; }
inline const uint160 operator<<(const uint160& a, unsigned int shift)        { return uint160(a) <<= shift; }
inline const uint160 operator>>(const uint160& a, unsigned int shift)        { return uint160(a) >>= shift; }

inline const uint160 operator^(const base_uint160& a, const base_uint160& b) { return uint160(a) ^= b; }
inline const uint160 operator&(const base_uint160& a, const base_uint160& b) { return uint160(a) &= b; }
inline const uint160 operator|(const base_uint160& a, const base_uint160& b) { return uint160(a) |= b; }
inline const uint160 operator+(const base_uint160& a, const base_uint160& b) { return uint160(a) += b; }
inline const uint160 operator-(const base_uint160& a, const base_uint160& b) { return uint160(a) -= b; }

inline bool operator<(const base_uint160& a, const uint160& b)          { return (base_uint160)a <  (base_uint160)b; }
inline bool operator<=(const base_uint160& a, const uint160& b)         { return (base_uint160)a <= (base_uint160)b; }
inline bool operator>(const base_uint160& a, const uint160& b)          { return (base_uint160)a >  (base_uint160)b; }
inline bool operator>=(const base_uint160& a, const uint160& b)         { return (base_uint160)a >= (base_uint160)b; }
inline bool operator==(const base_uint160& a, const uint160& b)         { return (base_uint160)a == (base_uint160)b; }
inline bool operator!=(const base_uint160& a, const uint160& b)         { return (base_uint160)a != (base_uint160)b; }
inline const uint160 operator^(const base_uint160& a, const uint160& b) { return (base_uint160)a ^  (base_uint160)b; }
inline const uint160 operator&(const base_uint160& a, const uint160& b) { return (base_uint160)a &  (base_uint160)b; }
inline const uint160 operator|(const base_uint160& a, const uint160& b) { return (base_uint160)a |  (base_uint160)b; }
inline const uint160 operator+(const base_uint160& a, const uint160& b) { return (base_uint160)a +  (base_uint160)b; }
inline const uint160 operator-(const base_uint160& a, const uint160& b) { return (base_uint160)a -  (base_uint160)b; }

inline bool operator<(const uint160& a, const base_uint160& b)          { return (base_uint160)a <  (base_uint160)b; }
inline bool operator<=(const uint160& a, const base_uint160& b)         { return (base_uint160)a <= (base_uint160)b; }
inline bool operator>(const uint160& a, const base_uint160& b)          { return (base_uint160)a >  (base_uint160)b; }
inline bool operator>=(const uint160& a, const base_uint160& b)         { return (base_uint160)a >= (base_uint160)b; }
inline bool operator==(const uint160& a, const base_uint160& b)         { return (base_uint160)a == (base_uint160)b; }
inline bool operator!=(const uint160& a, const base_uint160& b)         { return (base_uint160)a != (base_uint160)b; }
inline const uint160 operator^(const uint160& a, const base_uint160& b) { return (base_uint160)a ^  (base_uint160)b; }
inline const uint160 operator&(const uint160& a, const base_uint160& b) { return (base_uint160)a &  (base_uint160)b; }
inline const uint160 operator|(const uint160& a, const base_uint160& b) { return (base_uint160)a |  (base_uint160)b; }
inline const uint160 operator+(const uint160& a, const base_uint160& b) { return (base_uint160)a +  (base_uint160)b; }
inline const uint160 operator-(const uint160& a, const base_uint160& b) { return (base_uint160)a -  (base_uint160)b; }

inline bool operator<(const uint160& a, const uint160& b)               { return (base_uint160)a <  (base_uint160)b; }
inline bool operator<=(const uint160& a, const uint160& b)              { return (base_uint160)a <= (base_uint160)b; }
inline bool operator>(const uint160& a, const uint160& b)               { return (base_uint160)a >  (base_uint160)b; }
inline bool operator>=(const uint160& a, const uint160& b)              { return (base_uint160)a >= (base_uint160)b; }
inline bool operator==(const uint160& a, const uint160& b)              { return (base_uint160)a == (base_uint160)b; }
inline bool operator!=(const uint160& a, const uint160& b)              { return (base_uint160)a != (base_uint160)b; }
inline const uint160 operator^(const uint160& a, const uint160& b)      { return (base_uint160)a ^  (base_uint160)b; }
inline const uint160 operator&(const uint160& a, const uint160& b)      { return (base_uint160)a &  (base_uint160)b; }
inline const uint160 operator|(const uint160& a, const uint160& b)      { return (base_uint160)a |  (base_uint160)b; }
inline const uint160 operator+(const uint160& a, const uint160& b)      { return (base_uint160)a +  (base_uint160)b; }
inline const uint160 operator-(const uint160& a, const uint160& b)      { return (base_uint160)a -  (base_uint160)b; }






//////////////////////////////////////////////////////////////////////////////
//
// uint256
//

/** 256-bit unsigned integer */
class uint256 : public base_uint256
{
public:
    typedef base_uint256 basetype;

    uint256()
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = 0;
    }

    uint256(const basetype& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
    }

    uint256& operator=(const basetype& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
        return *this;
    }

    uint256(uint64 b)
    {
        Set64(b, 0, true);
    }

    explicit uint256(const std::string& str)
    {
        SetHex(str);
    }

    explicit uint256(const std::vector<unsigned char>& vch)
    {
        if (vch.size() == sizeof(pn))
        {
            int j;
            for (int i = 0; i < WIDTH; ++i)
            {
                j = (WIDTH-1 - i) * 4;
                pn[i] = vch[j]
                     | (vch[j+1] <<  8)
                     | (vch[j+2] << 16)
                     | (vch[j+3] << 24);
            }
        }
        else
            *this = 0;
    }
};

inline bool operator==(const uint256& a, uint64 b)                           { return (base_uint256)a == b; }
inline bool operator!=(const uint256& a, uint64 b)                           { return (base_uint256)a != b; }
inline const uint256 operator<<(const base_uint256& a, unsigned int shift)   { return uint256(a) <<= shift; }
inline const uint256 operator>>(const base_uint256& a, unsigned int shift)   { return uint256(a) >>= shift; }
inline const uint256 operator<<(const uint256& a, unsigned int shift)        { return uint256(a) <<= shift; }
inline const uint256 operator>>(const uint256& a, unsigned int shift)        { return uint256(a) >>= shift; }

inline const uint256 operator^(const base_uint256& a, const base_uint256& b) { return uint256(a) ^= b; }
inline const uint256 operator&(const base_uint256& a, const base_uint256& b) { return uint256(a) &= b; }
inline const uint256 operator|(const base_uint256& a, const base_uint256& b) { return uint256(a) |= b; }
inline const uint256 operator+(const base_uint256& a, const base_uint256& b) { return uint256(a) += b; }
inline const uint256 operator-(const base_uint256& a, const base_uint256& b) { return uint256(a) -= b; }

inline bool operator<(const base_uint256& a, const uint256& b)          { return (base_uint256)a <  (base_uint256)b; }
inline bool operator<=(const base_uint256& a, const uint256& b)         { return (base_uint256)a <= (base_uint256)b; }
inline bool operator>(const base_uint256& a, const uint256& b)          { return (base_uint256)a >  (base_uint256)b; }
inline bool operator>=(const base_uint256& a, const uint256& b)         { return (base_uint256)a >= (base_uint256)b; }
inline bool operator==(const base_uint256& a, const uint256& b)         { return (base_uint256)a == (base_uint256)b; }
inline bool operator!=(const base_uint256& a, const uint256& b)         { return (base_uint256)a != (base_uint256)b; }
inline const uint256 operator^(const base_uint256& a, const uint256& b) { return (base_uint256)a ^  (base_uint256)b; }
inline const uint256 operator&(const base_uint256& a, const uint256& b) { return (base_uint256)a &  (base_uint256)b; }
inline const uint256 operator|(const base_uint256& a, const uint256& b) { return (base_uint256)a |  (base_uint256)b; }
inline const uint256 operator+(const base_uint256& a, const uint256& b) { return (base_uint256)a +  (base_uint256)b; }
inline const uint256 operator-(const base_uint256& a, const uint256& b) { return (base_uint256)a -  (base_uint256)b; }

inline bool operator<(const uint256& a, const base_uint256& b)          { return (base_uint256)a <  (base_uint256)b; }
inline bool operator<=(const uint256& a, const base_uint256& b)         { return (base_uint256)a <= (base_uint256)b; }
inline bool operator>(const uint256& a, const base_uint256& b)          { return (base_uint256)a >  (base_uint256)b; }
inline bool operator>=(const uint256& a, const base_uint256& b)         { return (base_uint256)a >= (base_uint256)b; }
inline bool operator==(const uint256& a, const base_uint256& b)         { return (base_uint256)a == (base_uint256)b; }
inline bool operator!=(const uint256& a, const base_uint256& b)         { return (base_uint256)a != (base_uint256)b; }
inline const uint256 operator^(const uint256& a, const base_uint256& b) { return (base_uint256)a ^  (base_uint256)b; }
inline const uint256 operator&(const uint256& a, const base_uint256& b) { return (base_uint256)a &  (base_uint256)b; }
inline const uint256 operator|(const uint256& a, const base_uint256& b) { return (base_uint256)a |  (base_uint256)b; }
inline const uint256 operator+(const uint256& a, const base_uint256& b) { return (base_uint256)a +  (base_uint256)b; }
inline const uint256 operator-(const uint256& a, const base_uint256& b) { return (base_uint256)a -  (base_uint256)b; }

inline bool operator<(const uint256& a, const uint256& b)               { return (base_uint256)a <  (base_uint256)b; }
inline bool operator<=(const uint256& a, const uint256& b)              { return (base_uint256)a <= (base_uint256)b; }
inline bool operator>(const uint256& a, const uint256& b)               { return (base_uint256)a >  (base_uint256)b; }
inline bool operator>=(const uint256& a, const uint256& b)              { return (base_uint256)a >= (base_uint256)b; }
inline bool operator==(const uint256& a, const uint256& b)              { return (base_uint256)a == (base_uint256)b; }
inline bool operator!=(const uint256& a, const uint256& b)              { return (base_uint256)a != (base_uint256)b; }
inline const uint256 operator^(const uint256& a, const uint256& b)      { return (base_uint256)a ^  (base_uint256)b; }
inline const uint256 operator&(const uint256& a, const uint256& b)      { return (base_uint256)a &  (base_uint256)b; }
inline const uint256 operator|(const uint256& a, const uint256& b)      { return (base_uint256)a |  (base_uint256)b; }
inline const uint256 operator+(const uint256& a, const uint256& b)      { return (base_uint256)a +  (base_uint256)b; }
inline const uint256 operator-(const uint256& a, const uint256& b)      { return (base_uint256)a -  (base_uint256)b; }










#ifdef TEST_UINT256

inline int Testuint256AdHoc(std::vector<std::string> vArg)
{
    uint256 g(0);


    printf("%s\n", g.ToString().c_str());
    g--;  printf("g--\n");
    printf("%s\n", g.ToString().c_str());
    g--;  printf("g--\n");
    printf("%s\n", g.ToString().c_str());
    g++;  printf("g++\n");
    printf("%s\n", g.ToString().c_str());
    g++;  printf("g++\n");
    printf("%s\n", g.ToString().c_str());
    g++;  printf("g++\n");
    printf("%s\n", g.ToString().c_str());
    g++;  printf("g++\n");
    printf("%s\n", g.ToString().c_str());



    uint256 a(7);
    printf("a=7\n");
    printf("%s\n", a.ToString().c_str());

    uint256 b;
    printf("b undefined\n");
    printf("%s\n", b.ToString().c_str());
    int c = 3;

    a = c;
    a.pn[4] = 15;
    printf("%s\n", a.ToString().c_str());
    uint256 k(c);

    a = 5;
    a.pn[4] = 15;
    printf("%s\n", a.ToString().c_str());
    b = 1;
    b <<= 52;

    a |= b;

    a ^= 0x500;

    printf("a %s\n", a.ToString().c_str());

    a = a | b | (uint256)0x1000;


    printf("a %s\n", a.ToString().c_str());
    printf("b %s\n", b.ToString().c_str());

    a = 0xfffffffe;
    a.pn[3] = 9;

    printf("%s\n", a.ToString().c_str());
    a++;
    printf("%s\n", a.ToString().c_str());
    a++;
    printf("%s\n", a.ToString().c_str());
    a++;
    printf("%s\n", a.ToString().c_str());
    a++;
    printf("%s\n", a.ToString().c_str());

    a--;
    printf("%s\n", a.ToString().c_str());
    a--;
    printf("%s\n", a.ToString().c_str());
    a--;
    printf("%s\n", a.ToString().c_str());
    uint256 d = a--;
    printf("%s\n", d.ToString().c_str());
    printf("%s\n", a.ToString().c_str());
    a--;
    printf("%s\n", a.ToString().c_str());
    a--;
    printf("%s\n", a.ToString().c_str());

    d = a;

    printf("%s\n", d.ToString().c_str());

    for (int i = 0; i < uint256::WIDTH; ++i)
        printf("%08x", d.pn[i]);
    printf("\n");

    uint256 neg = d;
    neg = ~neg;
    printf("%s\n", neg.ToString().c_str());


    uint256 e = uint256("0xABCDEF123abcdef12345678909832180000011111111");
    printf("\n");
    printf("%s\n", e.ToString().c_str());


    printf("\n");
    uint256 x1 = uint256("0xABCDEF123abcdef12345678909832180000011111111");
    uint256 x2;
    printf("%s\n", x1.ToString().c_str());
    // NOTE: C++ doesn't define bitshifts greater than the left operand's precision, but we do
    for (int i = 0; i < 270; i += 4)
    {
        x2 = x1 << i;
        printf("%s\n", x2.ToString().c_str());
    }

    printf("\n");
    printf("%s\n", x1.ToString().c_str());
    for (int i = 0; i < 270; i += 4)
    {
        x2 = x1;
        x2 >>= i;
        printf("%s\n", x2.ToString().c_str());
    }


    for (int i = 0; i < 100; i++)
    {
        uint256 k = (~uint256(0) >> i);
        printf("%s\n", k.ToString().c_str());
    }

    for (int i = 0; i < 100; i++)
    {
        uint256 k = (~uint256(0) << i);
        printf("%s\n", k.ToString().c_str());
    }

    return (0);
}

#endif

#endif
