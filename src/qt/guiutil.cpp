#include <sstream>

#include "guiutil.h"
#include "bitcoinaddressvalidator.h"
#include "walletmodel.h"
#include "bitcoinunits.h"

#include <QString>
#include <QDateTime>
#include <QDoubleValidator>
#include <QFont>
#include <QLineEdit>
#include <QUrl>
#include <QTextDocument> // For Qt::escape
#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QFileDialog>
#include <QDesktopServices>
#include <QThread>

namespace GUIUtil {

QString dateTimeStr(const QDateTime &date)
{
    return date.date().toString(Qt::SystemLocaleShortDate) + QString(" ") + date.toString("hh:mm");
}

QString dateTimeStr(qint64 nTime)
{
    return dateTimeStr(QDateTime::fromTime_t((qint32)nTime));
}

QFont bitcoinAddressFont()
{
    QFont font("Monospace");
    font.setStyleHint(QFont::TypeWriter);
    return font;
}

void setupAddressWidget(QLineEdit *widget, QWidget *parent)
{
    widget->setMaxLength(BitcoinAddressValidator::MaxAddressLength);
    widget->setValidator(new BitcoinAddressValidator(parent));
    widget->setFont(bitcoinAddressFont());
}

void setupAmountWidget(QLineEdit *widget, QWidget *parent)
{
    QDoubleValidator *amountValidator = new QDoubleValidator(parent);
    amountValidator->setDecimals(8);
    amountValidator->setBottom(0.0);
    widget->setValidator(amountValidator);
    widget->setAlignment(Qt::AlignRight|Qt::AlignVCenter);
}

static
qint64 parseNumber(std::string strNumber, bool fHex)
{
    qint64 nAmount = 0;
    std::istringstream stream(strNumber);
    stream >> (fHex ? std::hex : std::dec) >> nAmount;
    return nAmount;
}

qint64 URIParseAmount(std::string strAmount)
{
    qint64 nAmount = 0;
    bool fHex = false;
    if (strAmount[0] == 'x' || strAmount[0] == 'X')
    {
        fHex = true;
        strAmount = strAmount.substr(1);
    }
    size_t nPosX = strAmount.find('X', 1);
    if (nPosX == std::string::npos)
        nPosX = strAmount.find('x', 1);
    int nExponent = 0;
    if (nPosX != std::string::npos)
        nExponent = parseNumber(strAmount.substr(nPosX + 1), fHex);
    else
    {
        // Non-compliant URI, assume standard units
        nExponent = fHex ? 4 : 8;
        nPosX = strAmount.size();
    }
    size_t nPosP = strAmount.find('.');
    size_t nFractionLen = 0;
    if (nPosP == std::string::npos)
        nPosP = nPosX;
    else
        nFractionLen = (nPosX - nPosP) - 1;
    nExponent -= nFractionLen;
    strAmount = strAmount.substr(0, nPosP) + (nFractionLen ? strAmount.substr(nPosP + 1, nFractionLen) : "");
    if (nExponent > 0)
        strAmount.append(nExponent, '0');
    else
    if (nExponent < 0)
        // WTF? truncate I guess
        strAmount = strAmount.substr(0, strAmount.size() + nExponent);
    nAmount = parseNumber(strAmount, fHex);
    return nAmount;
}

bool parseBitcoinURI(const QUrl &uri, SendCoinsRecipient *out)
{
    if(uri.scheme() != QString("bitcoin"))
        return false;

    SendCoinsRecipient rv;
    rv.address = uri.path();
    rv.amount = 0;
    QList<QPair<QString, QString> > items = uri.queryItems();
    for (QList<QPair<QString, QString> >::iterator i = items.begin(); i != items.end(); i++)
    {
        bool fShouldReturnFalse = false;
        if (i->first.startsWith("req-"))
        {
            i->first.remove(0, 4);
            fShouldReturnFalse = true;
        }

        if (i->first == "label")
        {
            rv.label = i->second;
            fShouldReturnFalse = false;
        }
        else if (i->first == "amount")
        {
            if(!i->second.isEmpty())
            {
                rv.amount = URIParseAmount((i->second).toStdString());
            }
            fShouldReturnFalse = false;
        }

        if (fShouldReturnFalse)
            return false;
    }
    if(out)
    {
        *out = rv;
    }
    return true;
}

bool parseBitcoinURI(QString uri, SendCoinsRecipient *out)
{
    // Convert bitcoin:// to bitcoin:
    //
    //    Cannot handle this later, because bitcoin:// will cause Qt to see the part after // as host,
    //    which will lowercase it (and thus invalidate the address).
    if(uri.startsWith("bitcoin://"))
    {
        uri.replace(0, 10, "bitcoin:");
    }
    QUrl uriInstance(uri);
    return parseBitcoinURI(uriInstance, out);
}

QString HtmlEscape(const QString& str, bool fMultiLine)
{
    QString escaped = Qt::escape(str);
    if(fMultiLine)
    {
        escaped = escaped.replace("\n", "<br>\n");
    }
    return escaped;
}

QString HtmlEscape(const std::string& str, bool fMultiLine)
{
    return HtmlEscape(QString::fromStdString(str), fMultiLine);
}

void copyEntryData(QAbstractItemView *view, int column, int role)
{
    if(!view || !view->selectionModel())
        return;
    QModelIndexList selection = view->selectionModel()->selectedRows(column);

    if(!selection.isEmpty())
    {
        // Copy first item
        QApplication::clipboard()->setText(selection.at(0).data(role).toString());
    }
}

QString getSaveFileName(QWidget *parent, const QString &caption,
                                 const QString &dir,
                                 const QString &filter,
                                 QString *selectedSuffixOut)
{
    QString selectedFilter;
    QString myDir;
    if(dir.isEmpty()) // Default to user documents location
    {
        myDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
    }
    else
    {
        myDir = dir;
    }
    QString result = QFileDialog::getSaveFileName(parent, caption, myDir, filter, &selectedFilter);

    /* Extract first suffix from filter pattern "Description (*.foo)" or "Description (*.foo *.bar ...) */
    QRegExp filter_re(".* \\(\\*\\.(.*)[ \\)]");
    QString selectedSuffix;
    if(filter_re.exactMatch(selectedFilter))
    {
        selectedSuffix = filter_re.cap(1);
    }

    /* Add suffix if needed */
    QFileInfo info(result);
    if(!result.isEmpty())
    {
        if(info.suffix().isEmpty() && !selectedSuffix.isEmpty())
        {
            /* No suffix specified, add selected suffix */
            if(!result.endsWith("."))
                result.append(".");
            result.append(selectedSuffix);
        }
    }

    /* Return selected suffix if asked to */
    if(selectedSuffixOut)
    {
        *selectedSuffixOut = selectedSuffix;
    }
    return result;
}

Qt::ConnectionType blockingGUIThreadConnection()
{
    if(QThread::currentThread() != QCoreApplication::instance()->thread())
    {
        return Qt::BlockingQueuedConnection;
    }
    else
    {
        return Qt::DirectConnection;
    }
}

bool checkPoint(const QPoint &p, const QWidget *w)
{
  QWidget *atW = qApp->widgetAt(w->mapToGlobal(p));
  if(!atW) return false;
  return atW->topLevelWidget() == w;
}

bool isObscured(QWidget *w)
{

  return !(checkPoint(QPoint(0, 0), w)
           && checkPoint(QPoint(w->width() - 1, 0), w)
           && checkPoint(QPoint(0, w->height() - 1), w)
           && checkPoint(QPoint(w->width() - 1, w->height() - 1), w)
           && checkPoint(QPoint(w->width()/2, w->height()/2), w));
}

} // namespace GUIUtil

