// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include "amount.h"
#include "core.h"
#include "main.h"
#include "miner.h"
#include "script/standard.h"
#include "sync.h"
#include "txmempool.h"
#include "uint256.h"
#include "util.h"

#include <cmath>
#include <string>

bool CNodePolicy::IsStandardScript(const CScript& scriptPubKey, txnouttype& whichType)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    switch (whichType)
    {
        case TX_MULTISIG:
        {
            unsigned char m = vSolutions.front()[0];
            unsigned char n = vSolutions.back()[0];
            // Support up to x-of-3 multisig txns as standard
            if (n < 1 || n > 3)
                return false;
            if (m < 1 || m > n)
                return false;
            break;
        }

        case TX_NULL_DATA:
            // TX_NULL_DATA without any vSolutions is a lone OP_RETURN, which traditionally is accepted regardless of the -datacarrier option, so we skip the check.
            // If you want to filter lone OP_RETURNs, be sure to handle vSolutions being empty below where vSolutions.front() is accessed!
            if (vSolutions.size())
            {
                if (!nDataCarrierBytes)
                    return false;

                if (vSolutions.front().size() > nDataCarrierBytes)
                    return false;
            }

            break;

        default:
            // no other restrictions on standard scripts
            break;
    }

    return whichType != TX_NONSTANDARD;
}

bool CNodePolicy::IsStandardTx(const CTransaction& tx, std::string& reason)
{
    AssertLockHeld(cs_main);

    // Treat non-final transactions as non-standard to prevent a specific type
    // of double-spend attack, as well as DoS attacks. (if the transaction
    // can't be mined, the attacker isn't expending resources broadcasting it)
    // Basically we don't want to propagate transactions that can't be included in
    // the next block.
    //
    // However, IsFinalTx() is confusing... Without arguments, it uses
    // chainActive.Height() to evaluate nLockTime; when a block is accepted, chainActive.Height()
    // is set to the value of nHeight in the block. However, when IsFinalTx()
    // is called within CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a transaction can
    // be part of the *next* block, we need to call IsFinalTx() with one more
    // than chainActive.Height().
    //
    // Timestamps on the other hand don't get any special treatment, because we
    // can't know what timestamp the next block will have, and there aren't
    // timestamp applications where it matters.
    if (!IsFinalTx(tx, chainActive.Height() + 1)) {
        reason = "non-final";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_SIZE mitigates CPU exhaustion attacks.
    unsigned int sz = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);
    if (sz >= MAX_STANDARD_TX_SIZE) {
        reason = "tx-size";
        return false;
    }

    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys. (remember the 520 byte limit on redeemScript size) That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)+3=1627
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not
        // considered standard)
        if (txin.scriptSig.size() > 1650) {
            reason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            reason = "scriptsig-not-pushonly";
            return false;
        }
        if (!txin.scriptSig.HasCanonicalPushes()) {
            reason = "scriptsig-non-canonical-push";
            return false;
        }
    }

    unsigned int nDataOut = 0;
    txnouttype whichType;
    BOOST_FOREACH(const CTxOut& txout, tx.vout) {
        if (!IsStandardScript(txout.scriptPubKey, whichType)) {
            reason = "scriptpubkey";
            return false;
        }

        if (whichType == TX_NULL_DATA)
            nDataOut++;
        else if ((whichType == TX_MULTISIG) && (!fIsBareMultisigStd)) {
            reason = "bare-multisig";
            return false;
        } else if (txout.IsDust(::minRelayTxFee)) {
            reason = "dust";
            return false;
        }
    }

    // only one OP_RETURN txout is permitted
    if (nDataOut > 1) {
        reason = "multi-op-return";
        return false;
    }

    return true;
}

//
// Check transaction inputs to mitigate two
// potential denial-of-service attacks:
//
// 1. scriptSigs with extra data stuffed into them,
//    not consumed by scriptPubKey (or P2SH script)
// 2. P2SH scripts with a crazy number of expensive
//    CHECKSIG/CHECKMULTISIG operations
//
bool CNodePolicy::AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CTxOut& prev = mapInputs.GetOutputFor(tx.vin[i]);

        std::vector<std::vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;
        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
            return false;

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig
        // IsStandardScript() will have already returned false
        // and this method isn't called.
        std::vector<std::vector<unsigned char> > stack;
        if (!EvalScript(stack, tx.vin[i].scriptSig, false, BaseSignatureChecker()))
            return false;

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            std::vector<std::vector<unsigned char> > vSolutions2;
            txnouttype whichType2;
            if (Solver(subscript, whichType2, vSolutions2))
            {
                int tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
                if (tmpExpected < 0)
                    return false;
                nArgsExpected += tmpExpected;
            }
            else
            {
                // Any other Script with less than 15 sigops OK:
                unsigned int sigops = subscript.GetSigOpCount(true);
                // ... extra data left on the stack after execution is OK, too:
                return (sigops <= MAX_P2SH_SIGOPS);
            }
        }

        if (stack.size() != (unsigned int)nArgsExpected)
            return false;
    }

    return true;
}

CAmount CNodePolicy::GetMinRelayFee(const CTransaction& tx, unsigned int nBytes, bool fAllowFree)
{
    {
        LOCK(mempool.cs);
        uint256 hash = tx.GetHash();
        double dPriorityDelta = 0;
        CAmount nFeeDelta = 0;
        mempool.ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
        if (dPriorityDelta > 0 || nFeeDelta > 0)
            return 0;
    }

    CAmount nMinFee = ::minRelayTxFee.GetFee(nBytes);

    if (fAllowFree)
    {
        // There is a free transaction area in blocks created by most miners,
        // * If we are relaying we allow transactions up to DEFAULT_BLOCK_PRIORITY_SIZE - 1000
        //   to be considered to fall into this category. We don't want to encourage sending
        //   multiple transactions instead of one big transaction to avoid fees.
        if (nBytes < (DEFAULT_BLOCK_PRIORITY_SIZE - 1000))
            nMinFee = 0;
    }

    if (!MoneyRange(nMinFee))
        nMinFee = MAX_MONEY;
    return nMinFee;
}

bool CNodePolicy::AcceptTxPoolPreInputs(CTxMemPool& pool, CValidationState& state, const CTransaction& tx)
{
    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    std::string reason;
    if (fRequireStandardTx && !IsStandardTx(tx, reason))
        return state.DoS(0,
                         error("%s : nonstandard transaction: %s", __func__, reason),
                         REJECT_NONSTANDARD, reason);

    // Check for conflicts with in-memory transactions
    if (pool.lookupConflicts(tx, NULL))
    {
        // Disable replacement feature for now
        return false;
    }

    return true;
}

bool CNodePolicy::AcceptTxWithInputs(CTxMemPool& pool, CValidationState& state, const CTransaction& tx, CCoinsViewCache& view)
{
    // Check for non-standard pay-to-script-hash in inputs
    if (fRequireStandardTx && !AreInputsStandard(tx, view))
        return error("%s : nonstandard transaction input", __func__);

    // Check that the transaction doesn't have an excessive number of
    // sigops, making it impossible to mine. Since the coinbase transaction
    // itself can contain sigops MAX_TX_SIGOPS is less than
    // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
    // merely non-standard transaction.
    unsigned int nSigOps = GetLegacySigOpCount(tx);
    nSigOps += GetP2SHSigOpCount(tx, view);
    if (nSigOps > MAX_TX_SIGOPS)
        return state.DoS(0,
                         error("%s : too many sigops %s, %d > %d",
                               __func__, tx.GetHash().ToString(), nSigOps, MAX_TX_SIGOPS),
                         REJECT_NONSTANDARD, "bad-txns-too-many-sigops");

    return true;
}

bool CNodePolicy::AcceptMemPoolEntry(CTxMemPool& pool, CValidationState& state, CTxMemPoolEntry& entry, CCoinsViewCache& view, bool& fRateLimit)
{
    const CTransaction& tx = entry.GetTx();

    CAmount nFees = entry.GetFee();
    unsigned int nSize = entry.GetTxSize();

    // Don't accept it if it can't get into a block
    CAmount txMinFee = GetMinRelayFee(tx, nSize, true);
    if (nFees < txMinFee)
        return state.DoS(0, error("%s : not enough fees %s, %d < %d",
                                  __func__, tx.GetHash().ToString(), nFees, txMinFee),
                         REJECT_INSUFFICIENTFEE, "insufficient fee");

    // Continuously rate-limit free (really, very-low-fee)transactions
    // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
    // be annoying or make others' transactions take longer to confirm.
    fRateLimit = (nFees < ::minRelayTxFee.GetFee(nSize));

    return true;
}

bool CNodePolicy::RateLimitTx(CTxMemPool& pool, CValidationState& state, CTxMemPoolEntry& entry, CCoinsViewCache& view)
{
    static CCriticalSection csFreeLimiter;
    static double dFreeCount;
    static int64_t nLastTime;
    int64_t nNow = GetTime();

    LOCK(csFreeLimiter);

    // Use an exponentially decaying ~10-minute window:
    dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
    nLastTime = nNow;
    // -limitfreerelay unit is thousand-bytes-per-minute
    // At default rate it would take over a month to fill 1GB
    if (dFreeCount >= GetArg("-limitfreerelay", 15)*10*1000)
        return state.DoS(0, error("%s : free transaction rejected by rate limiter", __func__),
                         REJECT_INSUFFICIENTFEE, "insufficient priority");
    unsigned int nSize = entry.GetTxSize();
    LogPrint("mempool", "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
    dFreeCount += nSize;

    return true;
}


//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.
// The COrphan class keeps track of these 'temporary orphans' while
// CreateBlock is figuring out which transactions to include.
//
class COrphan
{
public:
    const CTransaction* ptx;
    std::set<uint256> setDependsOn;
    CFeeRate feeRate;
    double dPriority;

    COrphan(const CTransaction* ptxIn) : ptx(ptxIn), feeRate(0), dPriority(0)
    {
    }
};

// We want to sort transactions by priority and fee rate, so:
typedef boost::tuple<double, CFeeRate, const CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;

public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }

    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

bool CNodePolicy::BuildNewBlock(CBlockTemplate& blocktemplate, const CTxMemPool& pool, const CBlockIndex& indexPrev, CCoinsViewCache& view)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pool.cs);

    const int nNewBlockHeight = blocktemplate.nHeight;
    const uint64_t nBlockSize = blocktemplate.nBlockSize;

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

    // Priority order to process transactions
    std::list<COrphan> vOrphan; // list memory doesn't move
    std::map<uint256, std::vector<COrphan*> > mapDependers;
    bool fPrintPriority = GetBoolArg("-printpriority", false);

    // This vector will be sorted into a priority queue:
    std::vector<TxPriority> vecPriority;
    vecPriority.reserve(mempool.mapTx.size());
    for (std::map<uint256, CTxMemPoolEntry>::iterator mi = mempool.mapTx.begin();
         mi != mempool.mapTx.end(); ++mi)
    {
        const CTransaction& tx = mi->second.GetTx();
        if (tx.IsCoinBase() || !IsFinalTx(tx, nNewBlockHeight))
            continue;

        COrphan* porphan = NULL;
        double dPriority = 0;
        CAmount nTotalIn = 0;
        bool fMissingInputs = false;
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
            // Read prev transaction
            if (!view.HaveCoins(txin.prevout.hash))
            {
                // This should never happen; all transactions in the memory
                // pool should connect to either transactions in the chain
                // or other transactions in the memory pool.
                if (!mempool.mapTx.count(txin.prevout.hash))
                {
                    LogPrintf("ERROR: mempool transaction missing input\n");
                    if (fDebug) assert("mempool transaction missing input" == 0);
                    fMissingInputs = true;
                    if (porphan)
                        vOrphan.pop_back();
                    break;
                }

                // Has to wait for dependencies
                if (!porphan)
                {
                    // Use list for automatic deletion
                    vOrphan.push_back(COrphan(&tx));
                    porphan = &vOrphan.back();
                }
                mapDependers[txin.prevout.hash].push_back(porphan);
                porphan->setDependsOn.insert(txin.prevout.hash);
                nTotalIn += mempool.mapTx[txin.prevout.hash].GetTx().vout[txin.prevout.n].nValue;
                continue;
            }
            const CCoins* coins = view.AccessCoins(txin.prevout.hash);
            assert(coins);

            CAmount nValueIn = coins->vout[txin.prevout.n].nValue;
            nTotalIn += nValueIn;

            int nConf = nNewBlockHeight - coins->nHeight;

            dPriority += (double)nValueIn * nConf;
        }
        if (fMissingInputs) continue;

        // Priority is sum(valuein * age) / modified_txsize
        unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
        dPriority = tx.ComputePriority(dPriority, nTxSize);

        uint256 hash = tx.GetHash();
        mempool.ApplyDeltas(hash, dPriority, nTotalIn);

        CFeeRate feeRate(nTotalIn-tx.GetValueOut(), nTxSize);

        if (porphan)
        {
            porphan->dPriority = dPriority;
            porphan->feeRate = feeRate;
        }
        else
            vecPriority.push_back(TxPriority(dPriority, feeRate, &mi->second.GetTx()));
    }

    // Collect transactions into block
    bool fSortedByFee = (nBlockPrioritySize <= 0);

    TxPriorityCompare comparer(fSortedByFee);
    std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

    while (!vecPriority.empty())
    {
        // Take highest priority transaction off the priority queue:
        double dPriority = vecPriority.front().get<0>();
        CFeeRate feeRate = vecPriority.front().get<1>();
        const CTransaction& tx = *(vecPriority.front().get<2>());

        std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
        vecPriority.pop_back();

        // Policy size limit
        unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
        if (nBlockSize + nTxSize >= nBlockMaxSize)
            continue;

        // Skip free transactions if we're past the minimum block size:
        const uint256& hash = tx.GetHash();
        double dPriorityDelta = 0;
        CAmount nFeeDelta = 0;
        mempool.ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
        if (fSortedByFee && (dPriorityDelta <= 0) && (nFeeDelta <= 0) && (feeRate < ::minRelayTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
            continue;

        if (!blocktemplate.AddTransaction(tx, view))
            continue;

        if (fPrintPriority)
        {
            LogPrintf("priority %.1f fee %s txid %s\n",
                dPriority, feeRate.ToString(), tx.GetHash().ToString());
        }

        // Add transactions that depend on this one to the priority queue
        if (mapDependers.count(hash))
        {
            BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
            {
                if (!porphan->setDependsOn.empty())
                {
                    porphan->setDependsOn.erase(hash);
                    if (porphan->setDependsOn.empty())
                    {
                        vecPriority.push_back(TxPriority(porphan->dPriority, porphan->feeRate, porphan->ptx));
                        std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                    }
                }
            }
        }

        // Prioritise by fee once past the priority size or we run out of high-priority
        // transactions:
        if (!fSortedByFee &&
            ((nBlockSize + nTxSize >= nBlockPrioritySize) || !AllowFree(dPriority)))
        {
            fSortedByFee = true;
            comparer = TxPriorityCompare(fSortedByFee);
            std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
        }
    }

    return true;
}
