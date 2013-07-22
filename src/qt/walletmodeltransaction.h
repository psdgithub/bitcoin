#ifndef WALLETMODELTRANSACTION_H
#define WALLETMODELTRANSACTION_H

#include "walletmodel.h"

class SendCoinsRecipient;

/** Data model for a walletmodel transaction. */
class WalletModelTransaction
{
public:
    explicit WalletModelTransaction(const QList<SendCoinsRecipient> &recipients);
    ~WalletModelTransaction();

    QList<SendCoinsRecipient> getRecipients();

    CWalletTx *getTransaction();

    void setTransactionFee(int64_t newFee);
    int64_t getTransactionFee();

    uint64_t getTotalTransactionAmount();

    void newPossibleKeyChange(CWallet *wallet);
    CReserveKey *getPossibleKeyChange();

private:
    const QList<SendCoinsRecipient> recipients;
    CWalletTx *walletTransaction;
    CReserveKey *keyChange;
    int64_t fee;
    
public slots:
    
};

#endif // WALLETMODELTRANSACTION_H
