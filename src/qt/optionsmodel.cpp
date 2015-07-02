// Copyright (c) 2011-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "optionsmodel.h"

#include "bitcoinunits.h"
#include "guiutil.h"

#include "amount.h"
#include "init.h"
#include "main.h"
#include "net.h"
#include "txdb.h" // for -dbcache defaults

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif

#include <QNetworkProxy>
#include <QSettings>
#include <QStringList>

#include <boost/algorithm/string.hpp>

OptionsModel::OptionsModel(QObject *parent) :
    QAbstractListModel(parent)
{
    Init();
}

void OptionsModel::addOverriddenOption(const std::string &option)
{
    strOverriddenByCommandLine += QString::fromStdString(option) + "=" + QString::fromStdString(mapArgs[option]) + " ";
}

// Writes all missing QSettings with their default values
void OptionsModel::Init()
{
    QSettings settings;

    // Ensure restart flag is unset on client startup
    setRestartRequired(false);

    // These are Qt-only settings:

    // Window
    if (!settings.contains("fMinimizeToTray"))
        settings.setValue("fMinimizeToTray", false);
    fMinimizeToTray = settings.value("fMinimizeToTray").toBool();

    if (!settings.contains("fMinimizeOnClose"))
        settings.setValue("fMinimizeOnClose", false);
    fMinimizeOnClose = settings.value("fMinimizeOnClose").toBool();

    // Display
    if (!settings.contains("nDisplayUnit"))
        settings.setValue("nDisplayUnit", BitcoinUnits::BTC);
    nDisplayUnit = settings.value("nDisplayUnit").toInt();

    if (!settings.contains("strThirdPartyTxUrls"))
        settings.setValue("strThirdPartyTxUrls", "");
    strThirdPartyTxUrls = settings.value("strThirdPartyTxUrls", "").toString();

    if (!settings.contains("fCoinControlFeatures"))
        settings.setValue("fCoinControlFeatures", false);
    fCoinControlFeatures = settings.value("fCoinControlFeatures", false).toBool();

    filteredAddresses.clear();
    int size = settings.beginReadArray("filteredAddresses");
    for (int i = 0; i < size; i++) {
        settings.setArrayIndex(i);
        filteredAddresses.insert(CBitcoinAddress(settings.value("address").toString().toStdString()));
    }
    settings.endArray();

    // These are shared with the core or have a command-line parameter
    // and we want command-line parameters to overwrite the GUI settings.
    //
    // If setting doesn't exist create it with defaults.
    //
    // If SoftSetArg() or SoftSetBoolArg() return false we were overridden
    // by command-line and show this in the UI.

    // Main
    if (!settings.contains("nDatabaseCache"))
        settings.setValue("nDatabaseCache", (qint64)nDefaultDbCache);
    if (!SoftSetArg("-dbcache", settings.value("nDatabaseCache").toString().toStdString()))
        addOverriddenOption("-dbcache");

    if (!settings.contains("nThreadsScriptVerif"))
        settings.setValue("nThreadsScriptVerif", DEFAULT_SCRIPTCHECK_THREADS);
    if (!SoftSetArg("-par", settings.value("nThreadsScriptVerif").toString().toStdString()))
        addOverriddenOption("-par");

    // Wallet
#ifdef ENABLE_WALLET
    if (!settings.contains("bSpendZeroConfChange"))
        settings.setValue("bSpendZeroConfChange", true);
    if (!SoftSetBoolArg("-spendzeroconfchange", settings.value("bSpendZeroConfChange").toBool()))
        addOverriddenOption("-spendzeroconfchange");
#endif

    // Network
    if (!settings.contains("fUseUPnP"))
        settings.setValue("fUseUPnP", DEFAULT_UPNP);
    if (!SoftSetBoolArg("-upnp", settings.value("fUseUPnP").toBool()))
        addOverriddenOption("-upnp");

    if (!settings.contains("fListen"))
        settings.setValue("fListen", DEFAULT_LISTEN);
    if (!SoftSetBoolArg("-listen", settings.value("fListen").toBool()))
        addOverriddenOption("-listen");

    if (!settings.contains("fUseProxy"))
        settings.setValue("fUseProxy", false);
    if (!settings.contains("addrProxy"))
        settings.setValue("addrProxy", "127.0.0.1:9050");
    // Only try to set -proxy, if user has enabled fUseProxy
    if (settings.value("fUseProxy").toBool() && !SoftSetArg("-proxy", settings.value("addrProxy").toString().toStdString()))
        addOverriddenOption("-proxy");
    else if(!settings.value("fUseProxy").toBool() && !GetArg("-proxy", "").empty())
        addOverriddenOption("-proxy");

    // Display
    if (!settings.contains("language"))
        settings.setValue("language", "");
    if (!SoftSetArg("-lang", settings.value("language").toString().toStdString()))
        addOverriddenOption("-lang");

    // Advanced
    nDustLimit = settings.value("nDustLimit").toLongLong();

    language = settings.value("language").toString();
}

void OptionsModel::Reset()
{
    QSettings settings;

    // Remove all entries from our QSettings object
    settings.clear();

    // default setting for OptionsModel::StartAtStartup - disabled
    if (GUIUtil::GetStartOnSystemStartup())
        GUIUtil::SetStartOnSystemStartup(false);
}

int OptionsModel::rowCount(const QModelIndex & parent) const
{
    return OptionIDRowCount;
}

// read QSettings values and return them
QVariant OptionsModel::data(const QModelIndex & index, int role) const
{
    if(role == Qt::EditRole)
    {
        QSettings settings;
        switch(index.row())
        {
        case StartAtStartup:
            return GUIUtil::GetStartOnSystemStartup();
        case MinimizeToTray:
            return fMinimizeToTray;
        case MapPortUPnP:
#ifdef USE_UPNP
            return settings.value("fUseUPnP");
#else
            return false;
#endif
        case MinimizeOnClose:
            return fMinimizeOnClose;

        // default proxy
        case ProxyUse:
            return settings.value("fUseProxy", false);
        case ProxyIP: {
            // contains IP at index 0 and port at index 1
            QStringList strlIpPort = settings.value("addrProxy").toString().split(":", QString::SkipEmptyParts);
            return strlIpPort.at(0);
        }
        case ProxyPort: {
            // contains IP at index 0 and port at index 1
            QStringList strlIpPort = settings.value("addrProxy").toString().split(":", QString::SkipEmptyParts);
            return strlIpPort.at(1);
        }

#ifdef ENABLE_WALLET
        case SpendZeroConfChange:
            return settings.value("bSpendZeroConfChange");
#endif
        case DisplayUnit:
            return nDisplayUnit;
        case ThirdPartyTxUrls:
            return strThirdPartyTxUrls;
        case Language:
            return settings.value("language");
        case CoinControlFeatures:
            return fCoinControlFeatures;
        case DustLimit:
            return QVariant(qint64(nDustLimit));
        case FilteredAddresses:
        {
            std::string s;
            BOOST_FOREACH(const CBitcoinAddress& addr, filteredAddresses) {
                s += addr.ToString() + "\n";
            }
            return QVariant(QString::fromStdString(s));
        }
        case DatabaseCache:
            return settings.value("nDatabaseCache");
        case ThreadsScriptVerif:
            return settings.value("nThreadsScriptVerif");
        case Listen:
            return settings.value("fListen");
        default:
            return QVariant();
        }
    }
    return QVariant();
}

// write QSettings values
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

        // default proxy
        case ProxyUse:
            if (settings.value("fUseProxy") != value) {
                settings.setValue("fUseProxy", value.toBool());
                setRestartRequired(true);
            }
            break;
        case ProxyIP: {
            // contains current IP at index 0 and current port at index 1
            QStringList strlIpPort = settings.value("addrProxy").toString().split(":", QString::SkipEmptyParts);
            // if that key doesn't exist or has a changed IP
            if (!settings.contains("addrProxy") || strlIpPort.at(0) != value.toString()) {
                // construct new value from new IP and current port
                QString strNewValue = value.toString() + ":" + strlIpPort.at(1);
                settings.setValue("addrProxy", strNewValue);
                setRestartRequired(true);
            }
        }
        break;
        case ProxyPort: {
            // contains current IP at index 0 and current port at index 1
            QStringList strlIpPort = settings.value("addrProxy").toString().split(":", QString::SkipEmptyParts);
            // if that key doesn't exist or has a changed port
            if (!settings.contains("addrProxy") || strlIpPort.at(1) != value.toString()) {
                // construct new value from current IP and new port
                QString strNewValue = strlIpPort.at(0) + ":" + value.toString();
                settings.setValue("addrProxy", strNewValue);
                setRestartRequired(true);
            }
        }
        break;
#ifdef ENABLE_WALLET
        case SpendZeroConfChange:
            if (settings.value("bSpendZeroConfChange") != value) {
                settings.setValue("bSpendZeroConfChange", value);
                setRestartRequired(true);
            }
            break;
#endif
        case DisplayUnit:
            setDisplayUnit(value);
            break;
        case ThirdPartyTxUrls:
            if (strThirdPartyTxUrls != value.toString()) {
                strThirdPartyTxUrls = value.toString();
                settings.setValue("strThirdPartyTxUrls", strThirdPartyTxUrls);
                setRestartRequired(true);
            }
            break;
        case Language:
            if (settings.value("language") != value) {
                settings.setValue("language", value);
                setRestartRequired(true);
            }
            break;
        case CoinControlFeatures:
            fCoinControlFeatures = value.toBool();
            settings.setValue("fCoinControlFeatures", fCoinControlFeatures);
            emit coinControlFeaturesChanged(fCoinControlFeatures);
            break;
        case DatabaseCache:
            if (settings.value("nDatabaseCache") != value) {
                settings.setValue("nDatabaseCache", value);
                setRestartRequired(true);
            }
            break;
        case ThreadsScriptVerif:
            if (settings.value("nThreadsScriptVerif") != value) {
                settings.setValue("nThreadsScriptVerif", value);
                setRestartRequired(true);
            }
            break;
        case Listen:
            if (settings.value("fListen") != value) {
                settings.setValue("fListen", value);
                setRestartRequired(true);
            }
            break;
        case DustLimit:
            nDustLimit = value.toLongLong();
            settings.setValue("nDustLimit", qint64(nDustLimit));
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

/** Updates current unit in memory, settings and emits displayUnitChanged(newUnit) signal */
void OptionsModel::setDisplayUnit(const QVariant &value)
{
    if (!value.isNull())
    {
        QSettings settings;
        nDisplayUnit = value.toInt();
        settings.setValue("nDisplayUnit", nDisplayUnit);
        emit displayUnitChanged(nDisplayUnit);
    }
}

bool OptionsModel::getProxySettings(QNetworkProxy& proxy) const
{
    // Directly query current base proxy, because
    // GUI settings can be overridden with -proxy.
    proxyType curProxy;
    if (GetProxy(NET_IPV4, curProxy)) {
        proxy.setType(QNetworkProxy::Socks5Proxy);
        proxy.setHostName(QString::fromStdString(curProxy.proxy.ToStringIP()));
        proxy.setPort(curProxy.proxy.GetPort());

        return true;
    }
    else
        proxy.setType(QNetworkProxy::NoProxy);

    return false;
}

void OptionsModel::setRestartRequired(bool fRequired)
{
    QSettings settings;
    return settings.setValue("fRestartRequired", fRequired);
}

bool OptionsModel::isRestartRequired()
{
    QSettings settings;
    return settings.value("fRestartRequired", false).toBool();
}

qint64 OptionsModel::getDustLimit()
{
    return nDustLimit;
}
