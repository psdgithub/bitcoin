// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include "core.h"

#include <stdint.h>

class CBlockIndex;
class CCoinsViewCache;
class CReserveKey;
class CScript;
class CWallet;

class CBlockTemplate
{
public:
    CBlock block;
    int nHeight;
    uint64_t nBlockSize;
    CAmount nTotalTxFees;
    std::vector<CAmount> vTxFees;
    int64_t nBlockSigOps;
    std::vector<int64_t> vTxSigOps;

    bool AddTransaction(const CTransaction&, CCoinsViewCache&);
};

/** Run the miner threads */
void GenerateBitcoins(bool fGenerate, CWallet* pwallet, int nThreads);
/** Generate a new block, without valid proof-of-work */
CBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn);
CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey);
/** Modify the extranonce in a block */
void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
/** Check mined block */
bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey);

extern double dHashesPerSec;
extern int64_t nHPSTimerStart;

#endif // BITCOIN_MINER_H
