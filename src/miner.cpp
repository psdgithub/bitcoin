// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <inttypes.h>

#include "miner.h"

#include "core.h"
#include "main.h"
#include "net.h"
#ifdef ENABLE_WALLET
#include "wallet.h"
#endif
//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

int static FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

static const unsigned int pSHA256InitState[8] =
{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

void SHA256Transform(void* pstate, void* pinput, const void* pinit)
{
    SHA256_CTX ctx;
    unsigned char data[64];

    SHA256_Init(&ctx);

    for (int i = 0; i < 16; i++)
        ((uint32_t*)data)[i] = ByteReverse(((uint32_t*)pinput)[i]);

    for (int i = 0; i < 8; i++)
        ctx.h[i] = ((uint32_t*)pinit)[i];

    SHA256_Update(&ctx, data, sizeof(data));
    for (int i = 0; i < 8; i++)
        ((uint32_t*)pstate)[i] = ctx.h[i];
}

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.
// CTxInfo represents a logical transaction to potentially be included in blocks
// It stores extra metadata such as the subjective priority of a transaction at
// the time of building the block. When there are unconfirmed transactions that
// depend on other unconfirmed transactions, these "child" transactions' CTxInfo
// object factors in its "parents" to its priority and effective size; this way,
// the "child" can cover the "cost" of its "parents", and the "parents" are
// included into the block as part of the "child".
//
class CTxInfo;
typedef std::map<uint256, CTxInfo> mapInfo_t;

class CTxInfo
{
public:
    mapInfo_t *pmapInfoById;
    const CTransaction* ptx;
    uint256 hash;
private:
    set<uint256> setDependsOn;
public:
    set<uint256> setDependents;
    double dPriority;
    uint64_t nTxFee;
    int nTxSigOps;
    bool fInvalid;
    unsigned int nSize;
    unsigned int nEffectiveSizeCached;

    CTxInfo() : pmapInfoById(NULL), hash(0), fInvalid(false), nSize(0), nEffectiveSizeCached(0)
    {
        ptx = NULL;
        dPriority = nTxFee = 0;
    }

    void print() const
    {
        LogPrintf("CTxInfo(hash=%s, dPriority=%.1f, nTxFee=%d)\n",
               ptx->GetHash().ToString(), dPriority, nTxFee);
        BOOST_FOREACH(uint256 hash, setDependsOn)
            LogPrintf("   setDependsOn %s\n", hash.ToString());
    }

    void addDependsOn(const uint256& hashPrev)
    {
        setDependsOn.insert(hashPrev);
        nEffectiveSizeCached = 0;
    }

    void rmDependsOn(const uint256& hashPrev)
    {
        setDependsOn.erase(hashPrev);
        nEffectiveSizeCached = 0;
    }

    // effectiveSize handles inheriting the fInvalid flag as a side effect
    unsigned int effectiveSize()
    {
        if (fInvalid)
            return -1;

        if (nEffectiveSizeCached)
            return nEffectiveSizeCached;

        assert(pmapInfoById);

        if (!nSize)
            nSize = ::GetSerializeSize(*ptx, SER_NETWORK, PROTOCOL_VERSION);
        unsigned int nEffectiveSize = nSize;
        BOOST_FOREACH(const uint256& dephash, setDependsOn)
        {
            CTxInfo& depinfo = (*pmapInfoById)[dephash];
            nEffectiveSize += depinfo.effectiveSize();

            if (depinfo.fInvalid)
            {
                fInvalid = true;
                return -1;
            }
        }
        nEffectiveSizeCached = nEffectiveSize;
        return nEffectiveSize;
    }

    unsigned int effectiveSizeMod()
    {
        unsigned int nTxSizeMod = effectiveSize();
        const CTransaction &tx = *ptx;
        // In order to avoid disincentivizing cleaning up the UTXO set we don't count
        // the constant overhead for each txin and up to 110 bytes of scriptSig (which
        // is enough to cover a compressed pubkey p2sh redemption) for priority.
        // Providing any more cleanup incentive than making additional inputs free would
        // risk encouraging people to create junk outputs to redeem later.
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
            unsigned int offset = 41U + min(110U, (unsigned int)txin.scriptSig.size());
            if (nTxSizeMod > offset)
                nTxSizeMod -= offset;
        }
        return nTxSizeMod;
    }

    double getPriority()
    {
        // Priority is sum(valuein * age) / modified_txsize
        return dPriority / effectiveSizeMod();
    }

    double getFeeRate()
    {
        return nTxFee / effectiveSize();
    }

    unsigned int GetLegacySigOpCount()
    {
        assert(pmapInfoById);

        unsigned int n = ::GetLegacySigOpCount(*ptx);
        BOOST_FOREACH(const uint256& dephash, setDependsOn)
        {
            CTxInfo& depinfo = (*pmapInfoById)[dephash];
            n += depinfo.GetLegacySigOpCount();
        }
        return n;
    }

    bool DoInputs(CCoinsViewCache& view, CBlockIndex*pindexPrev, std::vector<CTxInfo*>& vAdded, unsigned int& nSigOpCounter)
    {
        const CTransaction& tx = *ptx;

        if (view.HaveCoins(hash))
            // Already included in block template
            return true;

        assert(pmapInfoById);

        BOOST_FOREACH(const uint256& dephash, setDependsOn)
        {
            CTxInfo& depinfo = (*pmapInfoById)[dephash];
            if (!depinfo.DoInputs(view, pindexPrev, vAdded, nSigOpCounter))
                return false;
        }

        if (!view.HaveInputs(tx))
            return false;

        nTxSigOps = GetP2SHSigOpCount(tx, view);
        nSigOpCounter += nTxSigOps;

        CValidationState state;
        if (!CheckInputs(tx, state, view, true, SCRIPT_VERIFY_P2SH))
            return false;

        CTxUndo txundo;
        UpdateCoins(tx, state, view, txundo, pindexPrev->nHeight+1, hash);

        vAdded.push_back(this);

        return true;
    }
};


uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

// We want to sort transactions by priority and fee, so:
typedef CTxInfo* TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a->getFeeRate() == b->getFeeRate())
                return a->getPriority() < b->getPriority();
            return a->getFeeRate() < b->getFeeRate();
        }
        else
        {
            if (a->getPriority() == b->getPriority())
                return a->getFeeRate() < b->getFeeRate();
            return a->getPriority() < b->getPriority();
        }
    }
};

CBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn)
{
    // Create new block
    auto_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = scriptPubKeyIn;

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    int64_t nFees = 0;
    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = chainActive.Tip();
        CCoinsViewCache view(*pcoinsTip, true);

        // Priority order to process transactions
        mapInfo_t mapInfoById;
        bool fPrintPriority = GetBoolArg("-printpriority", false);

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());

        for (map<uint256, CTxMemPoolEntry>::iterator mi = mempool.mapTx.begin();
             mi != mempool.mapTx.end(); ++mi)
        {
            const CTransaction& tx = mi->second.GetTx();

            const uint256& hash = tx.GetHash();
            CTxInfo& txinfo = mapInfoById[hash];
            txinfo.hash = hash;
            txinfo.pmapInfoById = &mapInfoById;
            txinfo.ptx = &tx;

            if (tx.IsCoinBase() || !IsFinalTx(tx, pindexPrev->nHeight + 1))
            {
                txinfo.fInvalid = true;
                continue;
            }

            double& dPriority = txinfo.dPriority;
            uint64_t& nTxFee = txinfo.nTxFee;
            int64_t nTotalIn = 0;
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                // Read prev transaction
                int64_t nValueIn;
                int nConf;
                if (view.HaveCoins(txin.prevout.hash))
                {
                    const CCoins &coins = view.GetCoins(txin.prevout.hash);
                    // Input is confirmed
                    nConf = pindexPrev->nHeight - coins.nHeight + 1;
                    nValueIn = coins.vout[txin.prevout.n].nValue;
                    dPriority += (double)nValueIn * nConf;
                }
                else
                if (mempool.mapTx.count(txin.prevout.hash))
                {
                    // Input is still unconfirmed
                    const uint256& hashPrev = txin.prevout.hash;
                    nValueIn = mempool.mapTx[hashPrev].GetTx().vout[txin.prevout.n].nValue;
                    txinfo.addDependsOn(hashPrev);
                    mapInfoById[hashPrev].setDependents.insert(hash);
                    nConf = 0;
                }
                else
                {
                    // We don't know where the input is
                    // In this case, it's impossible to include this transaction in a block, so mark it invalid and move on
                    txinfo.fInvalid = true;
                    LogPrintf("priority %s invalid input %s\n", txinfo.hash.ToString().substr(0,10).c_str(), txin.prevout.hash.ToString().substr(0,10).c_str());
                    goto nexttxn;
                }

                nTotalIn += nValueIn;
            }

            nTxFee = nTotalIn - tx.GetValueOut();

            mempool.ApplyDeltas(hash, dPriority, nTotalIn);

            vecPriority.push_back(&txinfo);

nexttxn:    (void)1;
        }

        // Collect transactions into block
        uint64_t nBlockSize = 1000;
        uint64_t nBlockTx = 0;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            CTxInfo& txinfo = *(vecPriority.front());
            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            if (txinfo.fInvalid)
                continue;

            const CTransaction& tx = *txinfo.ptx;
            double dPriority = txinfo.getPriority();
            double dFeePerKb = txinfo.getFeeRate();

            // Size limits
            unsigned int nTxSize = txinfo.effectiveSize();
            if (nBlockSize + nTxSize >= nBlockMaxSize)
                continue;

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = txinfo.GetLegacySigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Skip free transactions if we're past the minimum block size:
            const uint256& hash = tx.GetHash();
            double dPriorityDelta = 0;
            int64_t nFeeDelta = 0;
            mempool.ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
            if (fSortedByFee && (dPriorityDelta <= 0) && (nFeeDelta <= 0) && (dFeePerKb < CTransaction::nMinRelayTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
                continue;

            // Prioritise by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || !AllowFree(dPriority)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            // second layer cached modifications just for this transaction
            CCoinsViewCache viewTemp(view, true);

            std::vector<CTxInfo*> vAdded;
            if (!txinfo.DoInputs(viewTemp, pindexPrev, vAdded, nTxSigOps))
                continue;

            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // push changes from the second layer cache to the first one
            viewTemp.Flush();

            // Added
            nBlockSize += nTxSize;
            nBlockTx += vAdded.size();
            nBlockSigOps += nTxSigOps;

            if (fPrintPriority)
            {
                LogPrintf("priority %.1f feeperkb %.1f txid %s\n",
                       dPriority, dFeePerKb, tx.GetHash().ToString());
            }

            bool fResort = false;
            BOOST_FOREACH(CTxInfo* ptxinfo, vAdded)
            {
                pblock->vtx.push_back(*ptxinfo->ptx);
                pblocktemplate->vTxFees.push_back(ptxinfo->nTxFee);
                pblocktemplate->vTxSigOps.push_back(ptxinfo->nTxSigOps);
                nFees += ptxinfo->nTxFee;

                ptxinfo->fInvalid = true;
                if (!ptxinfo->setDependents.empty())
                {
                    fResort = true;
                    BOOST_FOREACH(const uint256& dhash, ptxinfo->setDependents)
                    {
                        CTxInfo& dtxinfo = mapInfoById[dhash];
                        dtxinfo.rmDependsOn(ptxinfo->hash);
                        fResort = true;
                    }
                }
            }
            if (fResort)
                // Re-sort the priority queue to pick up on improved standing
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        LogPrintf("CreateNewBlock(): total size %u\n", nBlockSize);

        pblock->vtx[0].vout[0].nValue = GetBlockValue(pindexPrev->nHeight+1, nFees);
        pblocktemplate->vTxFees[0] = -nFees;

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        UpdateTime(*pblock, pindexPrev);
        pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock);
        pblock->nNonce         = 0;
        pblock->vtx[0].vin[0].scriptSig = CScript() << OP_0 << OP_0;
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);

        CBlockIndex indexDummy(*pblock);
        indexDummy.pprev = pindexPrev;
        indexDummy.nHeight = pindexPrev->nHeight + 1;
        CCoinsViewCache viewNew(*pcoinsTip, true);
        CValidationState state;
        if (!ConnectBlock(*pblock, state, &indexDummy, viewNew, true))
            throw std::runtime_error("CreateNewBlock() : ConnectBlock failed");
    }

    return pblocktemplate.release();
}

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    pblock->vtx[0].vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(pblock->vtx[0].vin[0].scriptSig.size() <= 100);

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}


void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1)
{
    //
    // Pre-build hash buffers
    //
    struct
    {
        struct unnamed2
        {
            int nVersion;
            uint256 hashPrevBlock;
            uint256 hashMerkleRoot;
            unsigned int nTime;
            unsigned int nBits;
            unsigned int nNonce;
        }
        block;
        unsigned char pchPadding0[64];
        uint256 hash1;
        unsigned char pchPadding1[64];
    }
    tmp;
    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion       = pblock->nVersion;
    tmp.block.hashPrevBlock  = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
    tmp.block.nTime          = pblock->nTime;
    tmp.block.nBits          = pblock->nBits;
    tmp.block.nNonce         = pblock->nNonce;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    // Byte swap all the input buffer
    for (unsigned int i = 0; i < sizeof(tmp)/4; i++)
        ((unsigned int*)&tmp)[i] = ByteReverse(((unsigned int*)&tmp)[i]);

    // Precalc the first half of the first hash, which stays constant
    SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

    memcpy(pdata, &tmp.block, 128);
    memcpy(phash1, &tmp.hash1, 64);
}

#ifdef ENABLE_WALLET
//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//
double dHashesPerSec = 0.0;
int64_t nHPSTimerStart = 0;

//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// It operates on big endian data.  Caller does the byte reversing.
// All input buffers are 16-byte aligned.  nNonce is usually preserved
// between calls, but periodically or if nNonce is 0xffff0000 or above,
// the block is rebuilt and nNonce starts over at zero.
//
unsigned int static ScanHash_CryptoPP(char* pmidstate, char* pdata, char* phash1, char* phash, unsigned int& nHashesDone)
{
    unsigned int& nNonce = *(unsigned int*)(pdata + 12);
    for (;;)
    {
        // Crypto++ SHA256
        // Hash pdata using pmidstate as the starting state into
        // pre-formatted buffer phash1, then hash phash1 into phash
        nNonce++;
        SHA256Transform(phash1, pdata, pmidstate);
        SHA256Transform(phash, phash1, pSHA256InitState);

        // Return the nonce if the hash has at least some zero bits,
        // caller will check if it has enough to reach the target
        if (((unsigned short*)phash)[14] == 0)
            return nNonce;

        // If nothing found after trying for a while, return -1
        if ((nNonce & 0xffff) == 0)
        {
            nHashesDone = 0xffff+1;
            return (unsigned int) -1;
        }
        if ((nNonce & 0xfff) == 0)
            boost::this_thread::interruption_point();
    }
}

CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey)
{
    CPubKey pubkey;
    if (!reservekey.GetReservedKey(pubkey))
        return NULL;

    CScript scriptPubKey = CScript() << pubkey << OP_CHECKSIG;
    return CreateNewBlock(scriptPubKey);
}

bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    uint256 hash = pblock->GetHash();
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    if (hash > hashTarget)
        return false;

    //// debug print
    LogPrintf("BitcoinMiner:\n");
    LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex(), hashTarget.GetHex());
    pblock->print();
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue));

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("BitcoinMiner : generated block is stale");

        // Remove key from key pool
        reservekey.KeepKey();

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[pblock->GetHash()] = 0;
        }

        // Process this block the same as if we had received it from another node
        CValidationState state;
        if (!ProcessBlock(state, NULL, pblock))
            return error("BitcoinMiner : ProcessBlock, block not accepted");
    }

    return true;
}

void static BitcoinMiner(CWallet *pwallet)
{
    LogPrintf("BitcoinMiner started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("bitcoin-miner");

    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;

    try { while (true) {
        if (Params().NetworkID() != CChainParams::REGTEST) {
            // Busy-wait for the network to come online so we don't waste time mining
            // on an obsolete chain. In regtest mode we expect to fly solo.
            while (vNodes.empty())
                MilliSleep(1000);
        }

        //
        // Create new block
        //
        unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrev = chainActive.Tip();

        auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlockWithKey(reservekey));
        if (!pblocktemplate.get())
            return;
        CBlock *pblock = &pblocktemplate->block;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        LogPrintf("Running BitcoinMiner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
               ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

        //
        // Pre-build hash buffers
        //
        char pmidstatebuf[32+16]; char* pmidstate = alignup<16>(pmidstatebuf);
        char pdatabuf[128+16];    char* pdata     = alignup<16>(pdatabuf);
        char phash1buf[64+16];    char* phash1    = alignup<16>(phash1buf);

        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        unsigned int& nBlockTime = *(unsigned int*)(pdata + 64 + 4);
        unsigned int& nBlockBits = *(unsigned int*)(pdata + 64 + 8);
        unsigned int& nBlockNonce = *(unsigned int*)(pdata + 64 + 12);


        //
        // Search
        //
        int64_t nStart = GetTime();
        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
        uint256 hashbuf[2];
        uint256& hash = *alignup<16>(hashbuf);
        while (true)
        {
            unsigned int nHashesDone = 0;
            unsigned int nNonceFound;

            // Crypto++ SHA256
            nNonceFound = ScanHash_CryptoPP(pmidstate, pdata + 64, phash1,
                                            (char*)&hash, nHashesDone);

            // Check if something found
            if (nNonceFound != (unsigned int) -1)
            {
                for (unsigned int i = 0; i < sizeof(hash)/4; i++)
                    ((unsigned int*)&hash)[i] = ByteReverse(((unsigned int*)&hash)[i]);

                if (hash <= hashTarget)
                {
                    // Found a solution
                    pblock->nNonce = ByteReverse(nNonceFound);
                    assert(hash == pblock->GetHash());

                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    CheckWork(pblock, *pwallet, reservekey);
                    SetThreadPriority(THREAD_PRIORITY_LOWEST);

                    // In regression test mode, stop mining after a block is found. This
                    // allows developers to controllably generate a block on demand.
                    if (Params().NetworkID() == CChainParams::REGTEST)
                        throw boost::thread_interrupted();

                    break;
                }
            }

            // Meter hashes/sec
            static int64_t nHashCounter;
            if (nHPSTimerStart == 0)
            {
                nHPSTimerStart = GetTimeMillis();
                nHashCounter = 0;
            }
            else
                nHashCounter += nHashesDone;
            if (GetTimeMillis() - nHPSTimerStart > 4000)
            {
                static CCriticalSection cs;
                {
                    LOCK(cs);
                    if (GetTimeMillis() - nHPSTimerStart > 4000)
                    {
                        dHashesPerSec = 1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
                        nHPSTimerStart = GetTimeMillis();
                        nHashCounter = 0;
                        static int64_t nLogTime;
                        if (GetTime() - nLogTime > 30 * 60)
                        {
                            nLogTime = GetTime();
                            LogPrintf("hashmeter %6.0f khash/s\n", dHashesPerSec/1000.0);
                        }
                    }
                }
            }

            // Check for stop or if block needs to be rebuilt
            boost::this_thread::interruption_point();
            if (vNodes.empty() && Params().NetworkID() != CChainParams::REGTEST)
                break;
            if (nBlockNonce >= 0xffff0000)
                break;
            if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                break;
            if (pindexPrev != chainActive.Tip())
                break;

            // Update nTime every few seconds
            UpdateTime(*pblock, pindexPrev);
            nBlockTime = ByteReverse(pblock->nTime);
            if (TestNet())
            {
                // Changing pblock->nTime can change work required on testnet:
                nBlockBits = ByteReverse(pblock->nBits);
                hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
            }
        }
    } }
    catch (boost::thread_interrupted)
    {
        LogPrintf("BitcoinMiner terminated\n");
        throw;
    }
}

void GenerateBitcoins(bool fGenerate, CWallet* pwallet, int nThreads)
{
    static boost::thread_group* minerThreads = NULL;

    if (nThreads < 0) {
        if (Params().NetworkID() == CChainParams::REGTEST)
            nThreads = 1;
        else
            nThreads = boost::thread::hardware_concurrency();
    }

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate)
        return;

    minerThreads = new boost::thread_group();
    for (int i = 0; i < nThreads; i++)
        minerThreads->create_thread(boost::bind(&BitcoinMiner, pwallet));
}

#endif

