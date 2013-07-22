#include "optionsmodel.h"

#include "bitcoinunits.h"
#include <boost/algorithm/string.hpp>

#include "init.h"
#include "guiutil.h"

#include "base58.h"
#include "net.h"
#include "walletdb.h"

#include <QSettings>

extern qint64 nTransactionFee; 

extern int64_t nDustLimit;
extern std::set<CBitcoinAddress> filteredAddresses;

OptionsModel::OptionsModel(QObject *parent) :
    QAbstractListModel(parent)
{
    Init();
}

bool static ApplyProxySettings()
{
    QSettings settings;
    CService addrProxy(settings.value("addrProxy", "127.0.0.1:9050").toString().toStdString());
    int nSocksVersion(settings.value("nSocksVersion", 5).toInt());
    if (!settings.value("fUseProxy", false).toBool()) {
        addrProxy = CService();
        nSocksVersion = 0;
        return false;
    }
    if (nSocksVersion && !addrProxy.IsValid())
        return false;
    if (!IsLimited(NET_IPV4))
        SetProxy(NET_IPV4, addrProxy, nSocksVersion, true);
    if (nSocksVersion > 4) {
#ifdef USE_IPV6
        if (!IsLimited(NET_IPV6))
            SetProxy(NET_IPV6, addrProxy, nSocksVersion, true);
#endif
        SetNameProxy(addrProxy, nSocksVersion);
    }
    return true;
}

void OptionsModel::Init()
{
    QSettings settings;

    // Ensure restart flag is unset on client startup
    setRestartRequired(false);

    // These are Qt-only settings with their defaults specified:

    // Window
    fMinimizeToTray = settings.value("fMinimizeToTray", false).toBool();
    fMinimizeOnClose = settings.value("fMinimizeOnClose", false).toBool();

    // Display
    //
    // use command-line value (as language can have one), if empty use QSettings value, if empty default to ""
    language = QString::fromStdString(GetArg("-lang", settings.value("language", "").toString().toStdString()));
    nDisplayUnit = settings.value("nDisplayUnit", BitcoinUnits::BTC).toInt();
    bDisplayAddresses = settings.value("bDisplayAddresses", false).toBool();

    // These are shared with the core or have a command-line parameter
    // and we want command-line parameters to override the GUI settings:

    // Main
    nTransactionFee = settings.value("nTransactionFee").toLongLong();
    nDustLimit = settings.value("nDustLimit").toLongLong();
    fCoinControlFeatures = settings.value("fCoinControlFeatures", false).toBool();

    filteredAddresses.clear();
    int size = settings.beginReadArray("filteredAddresses");
    for (int i = 0; i < size; i++) {
        settings.setArrayIndex(i);
        filteredAddresses.insert(CBitcoinAddress(settings.value("address").toString().toStdString()));
    }
    settings.endArray();

    // Network
    if (settings.contains("fUseUPnP"))
        SoftSetBoolArg("-upnp", settings.value("fUseUPnP").toBool());
    if (settings.contains("addrProxy") && settings.value("fUseProxy").toBool())
        SoftSetArg("-proxy", settings.value("addrProxy").toString().toStdString());
    if (settings.contains("nSocksVersion") && settings.value("fUseProxy").toBool())
        SoftSetArg("-socks", settings.value("nSocksVersion").toString().toStdString());

    // Display
    if (settings.contains("language"))
        SoftSetArg("-lang", language.toStdString());
}

void OptionsModel::Reset()
{
    QSettings settings;

    // Remove all entries from our QSettings object
    settings.clear();

    // default setting for OptionsModel::StartAtStartup - disabled
    if (GUIUtil::GetStartOnSystemStartup())
        GUIUtil::SetStartOnSystemStartup(false);

    // Ensure Upgrade() is not running again by setting the bImportFinished flag
    settings.setValue("bImportFinished", true);
}

bool OptionsModel::Upgrade()
{
    QSettings settings;

    if (settings.contains("bImportFinished"))
        return false; // Already upgraded

    settings.setValue("bImportFinished", true);

    // Move settings from old wallet.dat (if any):
    CWalletDB walletdb(strWalletFile);

    QList<QString> intOptions;
    intOptions << "nDisplayUnit" << "nTransactionFee";
    foreach(QString key, intOptions)
    {
        int value = 0;
        if (walletdb.ReadSetting(key.toStdString(), value))
        {
            settings.setValue(key, value);
            walletdb.EraseSetting(key.toStdString());
        }
    }
    QList<QString> boolOptions;
    boolOptions << "bDisplayAddresses" << "fMinimizeToTray" << "fMinimizeOnClose" << "fUseProxy" << "fUseUPnP";
    foreach(QString key, boolOptions)
    {
        bool value = false;
        if (walletdb.ReadSetting(key.toStdString(), value))
        {
            settings.setValue(key, value);
            walletdb.EraseSetting(key.toStdString());
        }
    }
    try
    {
        CAddress addrProxyAddress;
        if (walletdb.ReadSetting("addrProxy", addrProxyAddress))
        {
            settings.setValue("addrProxy", addrProxyAddress.ToStringIPPort().c_str());
            walletdb.EraseSetting("addrProxy");
        }
    }
    catch (std::ios_base::failure &e)
    {
        // 0.6.0rc1 saved this as a CService, which causes failure when parsing as a CAddress
        CService addrProxy;
        if (walletdb.ReadSetting("addrProxy", addrProxy))
        {
            settings.setValue("addrProxy", addrProxy.ToStringIPPort().c_str());
            walletdb.EraseSetting("addrProxy");
        }
    }
    ApplyProxySettings();
    Init();

    return true;
}


int OptionsModel::rowCount(const QModelIndex & parent) const
{
    return OptionIDRowCount;
}

QVariant OptionsModel::data(const QModelIndex & index, int role) const
{
    if(role == Qt::EditRole)
    {
        QSettings settings;
        switch(index.row())
        {
        case StartAtStartup:
            return QVariant(GUIUtil::GetStartOnSystemStartup());
        case MinimizeToTray:
            return QVariant(fMinimizeToTray);
        case MapPortUPnP:
#ifdef USE_UPNP
            return settings.value("fUseUPnP", GetBoolArg("-upnp", true));
#else
            return QVariant(false);
#endif
        case MinimizeOnClose:
            return QVariant(fMinimizeOnClose);

        // base proxy
        case ProxyUse: {
            proxyType proxy;
            return QVariant(GetProxy(NET_IPV4, proxy));
        }
        case ProxyIP: {
            proxyType proxy;
            if (GetProxy(NET_IPV4, proxy))
                return QVariant(QString::fromStdString(proxy.addrProxy.ToStringIP()));
            else
                return QVariant(QString::fromStdString("127.0.0.1"));
        }
        case ProxyPort: {
            proxyType proxy;
            if (GetProxy(NET_IPV4, proxy))
                return QVariant(proxy.addrProxy.GetPort());
            else
                return QVariant(9050);
        }
        case ProxySocksVersion: {
            proxyType proxy;
            if (GetProxy(NET_IPV4, proxy))
                return QVariant(proxy.nSocksVersion);
            else
                return QVariant(5);
        }
        case Fee:
            return QVariant(nTransactionFee);
        case DisplayUnit:
            return QVariant(nDisplayUnit);
        case DisplayAddresses:
            return QVariant(bDisplayAddresses);
        case Language: // return QSetting or default, not current state
            return settings.value("language", "");
        case CoinControlFeatures:
            return QVariant(fCoinControlFeatures);
        case DustLimit:
            return QVariant(nDustLimit);
        case FilteredAddresses: {
            std::string s;
            BOOST_FOREACH(const CBitcoinAddress& addr, filteredAddresses) {
                s += addr.ToString() + "\n";
            }
            return QVariant(QString::fromStdString(s));
        }
        default:
            return QVariant();
        }
    }
    return QVariant();
}

bool OptionsModel::setData(const QModelIndex & index, const QVariant & value, int role)
{
    bool successful = true; /* set to false on parse error */
    if(role == Qt::EditRole)
    {
        QSettings settings;
        switch(index.row())
        {
        case StartAtStartup:
            successful = GUIUtil::SetStartOnSystemStartup(value.toBool());
            break;
        case MinimizeToTray:
            fMinimizeToTray = value.toBool();
            settings.setValue("fMinimizeToTray", fMinimizeToTray);
            break;
        case MapPortUPnP: // core option - can be changed on-the-fly
            settings.setValue("fUseUPnP", value.toBool());
            MapPort(value.toBool());
            break;
        case MinimizeOnClose:
            fMinimizeOnClose = value.toBool();
            settings.setValue("fMinimizeOnClose", fMinimizeOnClose);
            break;
        // base proxy
        case ProxyUse:
            settings.setValue("fUseProxy", value.toBool());
            setRestartRequired(true);
            successful = ApplyProxySettings();
            break;
        case ProxyIP: {
            proxyType proxy;
            proxy.addrProxy = CService("127.0.0.1", 9050);
            GetProxy(NET_IPV4, proxy);

            CNetAddr addr(value.toString().toStdString());
            proxy.addrProxy.SetIP(addr);
            settings.setValue("addrProxy", proxy.addrProxy.ToStringIPPort().c_str());
            setRestartRequired(true);
            successful = ApplyProxySettings();
        }
        break;
        case ProxyPort: {
            proxyType proxy;
            proxy.addrProxy = CService("127.0.0.1", 9050);
            GetProxy(NET_IPV4, proxy);

            proxy.addrProxy.SetPort(value.toInt());
            settings.setValue("addrProxy", proxy.addrProxy.ToStringIPPort().c_str());
            setRestartRequired(true);
            successful = ApplyProxySettings();
        }
        break;
        case ProxySocksVersion: {
            proxyType proxy;
            proxy.nSocksVersion = 5;
            GetProxy(NET_IPV4, proxy);

            proxy.nSocksVersion = value.toInt();
            settings.setValue("nSocksVersion", proxy.nSocksVersion);
            setRestartRequired(true);
            successful = ApplyProxySettings();
        }
        break;
        case Fee:
            nTransactionFee = value.toLongLong();
            settings.setValue("nTransactionFee", nTransactionFee);
            emit transactionFeeChanged(nTransactionFee);
            break;
        case DisplayUnit:
            nDisplayUnit = value.toInt();
            settings.setValue("nDisplayUnit", nDisplayUnit);
            emit displayUnitChanged(nDisplayUnit);
            break;
        case DisplayAddresses:
            bDisplayAddresses = value.toBool();
            settings.setValue("bDisplayAddresses", bDisplayAddresses);
            break;
        case Language:
            settings.setValue("language", value);
            setRestartRequired(true);
            break;
        case CoinControlFeatures: {
            fCoinControlFeatures = value.toBool();
            settings.setValue("fCoinControlFeatures", fCoinControlFeatures);
            emit coinControlFeaturesChanged(fCoinControlFeatures);
        }
        break;
        case DustLimit:
            nDustLimit = value.toLongLong();
            settings.setValue("nDustLimit", nDustLimit);
            break;
        case FilteredAddresses: {
            std::vector<std::string> addresses;
            std::string s = value.toString().toStdString();
            std::string::size_type prev_pos = 0, pos = 0;
            while ((pos = s.find("\n", pos)) != std::string::npos) {
                std::string substring(s.substr(prev_pos, pos-prev_pos));
                boost::algorithm::trim(substring);
                addresses.push_back(substring);
                prev_pos = ++pos;
            }
            addresses.push_back(s.substr(prev_pos, pos-prev_pos));

            filteredAddresses.clear();

            int i = 0;
            settings.beginWriteArray("filteredAddresses");
            BOOST_FOREACH(const std::string& addr, addresses) {
                CBitcoinAddress btaddr(addr);
                if (btaddr.IsValid()) {
                    filteredAddresses.insert(btaddr);
                    settings.setArrayIndex(i++);
                    settings.setValue("address", QString::fromStdString(btaddr.ToString()));
                }
            }
            settings.endArray();
        }
        break;
        default:
            break;
        }
    }
    emit dataChanged(index, index);

    return successful;
}

qint64 OptionsModel::getTransactionFee()
{
    return nTransactionFee;
}

bool OptionsModel::getProxySettings(QString& proxyIP, quint16 &proxyPort) const
{
    std::string proxy = GetArg("-proxy", "");
    if (proxy.empty()) return false;

    CService addrProxy(proxy);
    proxyIP = QString(addrProxy.ToStringIP().c_str());
    proxyPort = addrProxy.GetPort();
    return true;
}

bool OptionsModel::getCoinControlFeatures()
{
    return fCoinControlFeatures;
}

qint64 OptionsModel::getDustLimit()
{
    return nDustLimit;
}
void OptionsModel::setRestartRequired(bool fRequired)
{
    QSettings settings;
    return settings.setValue("fRestartRequired", fRequired);
}

bool OptionsModel::isRestartRequired()
{
    QSettings settings;
    return settings.value("fRestartRequired").toBool();
}
