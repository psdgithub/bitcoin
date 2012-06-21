// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "bitcoinrpc.h"
#include "db.h"
#include "init.h"
#include "main.h"
#include "wallet.h"

using namespace std;
using namespace boost;
using namespace json_spirit;

// These are all in bitcoinrpc.cpp:
extern Object JSONRPCError(int code, const string& message);
extern int64 AmountFromValue(const Value& value);
extern Value ValueFromAmount(int64 amount);
extern void TxToJSON(const CTransaction &tx, Object& entry, const Object& decompositions);
extern std::string HelpRequiringPassphrase();
extern void EnsureWalletIsUnlocked();

Value listunspent(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listunspent [minconf=1] [maxconf=999999]\n"
            "Returns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
            "Returns an array of 4-element arrays, each of which is:\n"
            "[transaction id, output, amount, confirmations]");

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    int nMaxDepth = 999999;
    if (params.size() > 1)
        nMaxDepth = params[1].get_int();

    Array results;
    vector<COutput> vecOutputs;
    pwalletMain->AvailableCoins(vecOutputs, false);
    BOOST_FOREACH(const COutput& out, vecOutputs)
    {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        int64 nValue = out.tx->vout[out.i].nValue;
        Array entry;
        entry.push_back(out.tx->GetHash().GetHex());
        entry.push_back(out.i);
        entry.push_back(ValueFromAmount(nValue));
        entry.push_back(out.nDepth);
        results.push_back(entry);
    }

    return results;
}

Value getrawtx(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getrawtx <txid>\n"
            "Returns hexadecimal-encoded, serialized transaction data\n"
            "for <txid>. Returns an error if <txid> is unknown.\n");

    uint256 hash;
    hash.SetHex(params[0].get_str());

    CTransaction tx;
    uint256 hashBlock;
    if (!GetTransaction(hash, tx, hashBlock))
        throw JSONRPCError(-5, "No information available about transaction");

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}

Value createrawtx(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "createrawtx [[\"txid\",n],...] {address:amount,...}\n"
            "Create a transaction spending given inputs\n"
            "(array of (hex transaction id, output number) pairs),\n"
            "sending to given address(es).\n"
            "Returns the same information as gettransaction, plus an\n"
            "extra \"rawtx\" key with the hex-encoded transaction.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not stored in the wallet or transmitted to the network.");

    Array inputs = params[0].get_array();
    Object sendTo = params[1].get_obj();

    CTransaction rawTx;

    BOOST_FOREACH(Value& input, inputs)
    {
        const Array& a = input.get_array();
        if (a.size() < 2)
            throw JSONRPCError(-8, "Invalid parameter, expected 2 values");
        const string& txid = a[0].get_str();
        if (!IsHex(txid))
            throw JSONRPCError(-8, "Invalid parameter, expected hex txid");
        uint256 txhash(txid);
        int nOutput = a[1].get_int();

        CTxIn in(COutPoint(txhash, nOutput));
        rawTx.vin.push_back(in);
    }

    set<CBitcoinAddress> setAddress;
    BOOST_FOREACH(const Pair& s, sendTo)
    {
        CBitcoinAddress address(s.name_);
        if (!address.IsValid())
            throw JSONRPCError(-5, string("Invalid Bitcoin address:")+s.name_);

        if (setAddress.count(address))
            throw JSONRPCError(-8, string("Invalid parameter, duplicated address: ")+s.name_);
        setAddress.insert(address);

        CScript scriptPubKey;
        scriptPubKey.SetDestination(address.Get());
        int64 nAmount = AmountFromValue(s.value_);

        CTxOut out(nAmount, scriptPubKey);
        rawTx.vout.push_back(out);
    }

    Object result;
    TxToJSON(rawTx, result, Object());

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rawTx;
    result.push_back(Pair("rawtx", HexStr(ss.begin(), ss.end())));

    return result;
}

Value signrawtx(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "signrawtx <hex string> [<prevtx1>,...] [<privatekey1>,...]\n"
            "Sign inputs for raw transaction (serialized, hex-encoded).\n"
            "Second optional argument is an array of raw previous transactions that\n"
            "this transaction depends on but are not yet in the blockchain.\n"
            "Third optional argument is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"
            "Returns json object with keys:\n"
            "  rawtx : raw transaction with signature(s) (hex-encoded string)\n"
            "  complete : 1 if transaction has a complete set of signature (0 if not)"
            + HelpRequiringPassphrase());

    if (params.size() < 3)
        EnsureWalletIsUnlocked();

    vector<unsigned char> txData(ParseHex(params[0].get_str()));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    vector<CTransaction> txVariants;
    while (!ssData.empty())
    {
        try {
            CTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);
        }
        catch (std::exception &e) {
            throw JSONRPCError(-22, "TX decode failed");
        }
    }

    if (txVariants.empty())
        throw JSONRPCError(-22, "Missing transaction");    
    
    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CTransaction mergedTx(txVariants[0]);
    bool fComplete = true;

    // Fetch previous transactions (inputs):
    MapPrevTx mapPrevTx;
    {
        CTxDB txdb("r");
        map<uint256, CTxIndex> unused;
        bool fInvalid;
        mergedTx.FetchInputs(txdb, unused, false, false, mapPrevTx, fInvalid);
    }

    // Add previous txns given in the RPC call:
    if (params.size() > 1)
    {
        Array prevTxs = params[1].get_array();
        BOOST_FOREACH(Value& p, prevTxs)
        {
            vector<unsigned char> txData(ParseHex(p.get_str()));
            CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
            try {
                CTransaction prevTx;
                ssData >> prevTx;
                uint256 hash = prevTx.GetHash();
                mapPrevTx[hash].second = prevTx;
            }
            catch (std::exception &e) {
                throw JSONRPCError(-22, "TX decode failed");
            }
        }
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (params.size() > 2)
    {
        fGivenKeys = true;
        Array keys = params[2].get_array();
        BOOST_FOREACH(Value k, keys)
        {
            CBitcoinSecret vchSecret;
            bool fGood = vchSecret.SetString(k.get_str());
            if (!fGood)
                throw JSONRPCError(-5,"Invalid private key");
            CKey key;
            bool fCompressed;
            CSecret secret = vchSecret.GetSecret(fCompressed);
            key.SetSecret(secret, fCompressed);
            tempKeystore.AddKey(key);
        }
    }
    const CKeyStore& keystore = (fGivenKeys ? tempKeystore : *pwalletMain);

    // Sign what we can:
    for (int i = 0; i < mergedTx.vin.size(); i++)
    {
        CTxIn& txin = mergedTx.vin[i];
        uint256 hash = txin.prevout.hash;
        unsigned int n = txin.prevout.n;
        if (mapPrevTx.count(hash) == 0 || mapPrevTx[hash].second.vout.size() == 0)
        {
            fComplete = false;
            continue;
        }
        const CTransaction& prevTx = mapPrevTx[hash].second;
        if (n >= prevTx.vout.size())
            throw JSONRPCError(-22, "Bad raw transaction");
        CScript scriptPubKey = prevTx.vout[n].scriptPubKey;

        txin.scriptSig.clear();
        SignSignature(keystore, prevTx, mergedTx, i);

        // ... and merge in other signatures:
        BOOST_FOREACH(const CTransaction& txv, txVariants)
        {
            txin.scriptSig = CombineSignatures(scriptPubKey, mergedTx, i, txin.scriptSig, txv.vin[i].scriptSig);
        }
        if (!VerifySignature(prevTx, mergedTx, i, true, 0))
            fComplete = false;
    }

    Object result;
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << mergedTx;
    result.push_back(Pair("rawtx", HexStr(ssTx.begin(), ssTx.end())));
    result.push_back(Pair("complete", fComplete));

    return result;
}

Value sendrawtx(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "sendrawtx <hex string>\n"
            "Submits raw transaction (serialized, hex-encoded) to local node and network.");

    // parse hex string from parameter
    vector<unsigned char> txData(ParseHex(params[0].get_str()));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;

    // deserialize binary data stream
    try {
        ssData >> tx;
    }
    catch (std::exception &e) {
        throw JSONRPCError(-22, "TX decode failed");
    }

    // push to local node
    CTxDB txdb("r");
    if (!tx.AcceptToMemoryPool(txdb))
        throw JSONRPCError(-22, "TX rejected");

    SyncWithWallets(tx, NULL, true);

    // relay to network
    CInv inv(MSG_TX, tx.GetHash());
    RelayInventory(inv);

    return tx.GetHash().GetHex();
}
