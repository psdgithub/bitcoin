// Copyright (c) 2012 Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ENDIAN_H
#define BITCOIN_ENDIAN_H

#include <endian.h>
#if defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && __BYTE_ORDER == __LITTLE_ENDIAN
#   define DEFINITELY_LITTLE_ENDIAN
#elif defined(__i386) || defined(__i386__)
#   define DEFINITELY_LITTLE_ENDIAN
#endif

#endif
