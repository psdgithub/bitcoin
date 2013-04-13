/*
 * Qt4 bitcoin GUI.
 *
 * W.J. van der Laan 2011-2012
 * The Bitcoin Developers 2011-2013
 */
#ifndef WALLETSTACK_H
#define WALLETSTACK_H

#include <boost/shared_ptr.hpp>
#include <QMap>
#include <QStackedWidget>

class CWalletManager;

class AddressBookPage;
class BitcoinGUI;
class ClientModel;
class Notificator;
class OverviewPage;
class RPCConsole;
class SendCoinsDialog;
class SignVerifyMessageDialog;
class TransactionTableModel;
class TransactionView;
class WalletModel;
class WalletView;

QT_BEGIN_NAMESPACE
class QLabel;
class QModelIndex;
QT_END_NAMESPACE

/*
  WalletStack class. This class is a container for WalletView instances. It takes the place of centralWidget.
  It was added to support multiple wallet functionality. It communicates with both the client and the
  wallet models to give the user an up-to-date view of the current core state. It manages all the wallet views
  it contains and updates them accordingly.
 */
class WalletStack : public QStackedWidget
{
    Q_OBJECT

public:
    explicit WalletStack(QWidget *parent = 0);
    ~WalletStack();

    void setBitcoinGUI(BitcoinGUI *gui) { this->gui = gui; }

    void setClientModel(ClientModel *clientModel) { this->clientModel = clientModel; }

    bool addWallet(const QString& name, WalletModel *walletModel);
    bool removeWallet(const QString& name);

    void removeAllWallets();

    bool handleURI(const QString &uri);

    void showOutOfSyncWarning(bool fShow);

private:
    BitcoinGUI *gui;
    ClientModel *clientModel;
    QMap<QString, WalletView*> mapWalletViews;

    bool bOutOfSync;

public slots:
    void setCurrentWallet(const QString& name);

    /** Switch to overview (home) page */
    void gotoOverviewPage();
    /** Switch to history (transactions) page */
    void gotoHistoryPage();
    /** Switch to address book page */
    void gotoAddressBookPage();
    /** Switch to receive coins page */
    void gotoReceiveCoinsPage();
    /** Switch to send coins page */
    void gotoSendCoinsPage(QString addr = "");

    /** Show Sign/Verify Message dialog and switch to sign message tab */
    void gotoSignMessageTab(QString addr = "");
    /** Show Sign/Verify Message dialog and switch to verify message tab */
    void gotoVerifyMessageTab(QString addr = "");

    /** Encrypt the wallet */
    void encryptWallet(bool status);
    /** Backup the wallet */
    void backupWallet();
    /** Change encrypted wallet passphrase */
    void changePassphrase();
    /** Ask for passphrase to unlock wallet temporarily */
    void unlockWallet();

    /** Set the encryption status as shown in the UI.
     @param[in] status            current encryption status
     @see WalletModel::EncryptionStatus
     */
    void setEncryptionStatus();
};

#endif // WALLETSTACK_H
