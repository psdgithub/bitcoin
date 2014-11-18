// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQGLOBAL_H
#define BITCOIN_ZMQGLOBAL_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#if ENABLE_ZMQ
#include <zmq.h>
#endif

#include <stdarg.h>

void zmqError(const char *str);

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "primitives/block.h"
#include "primitives/transaction.h"

#include <string>

#endif // BITCOIN_ZMQGLOBAL_H
