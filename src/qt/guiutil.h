#ifndef GUIUTIL_H
#define GUIUTIL_H

#include <QString>

QT_BEGIN_NAMESPACE
class QFont;
class QLineEdit;
class QWidget;
class QDateTime;
class QUrl;
class QAbstractItemView;
QT_END_NAMESPACE
class SendCoinsRecipient;

/** Utility functions used by the Bitcoin Qt UI.
 */
namespace GUIUtil
{
    // Create human-readable string from date
    QString dateTimeStr(const QDateTime &datetime);
    QString dateTimeStr(qint64 nTime);

    // Render bitcoin addresses in monospace font
    QFont bitcoinAddressFont();

    // Set up widgets for address and amounts
    void setupAddressWidget(QLineEdit *widget, QWidget *parent);
    void setupAmountWidget(QLineEdit *widget, QWidget *parent);

    // Parse "bitcoin:" URL into recipient object, return true on succesful parsing
    // See Bitcoin URL definition discussion here: https://bitcointalk.org/index.php?topic=33490.0
    bool parseBitcoinURL(const QUrl *url, SendCoinsRecipient *out);

    // HTML escaping for rich text controls
    QString HtmlEscape(const QString& str, bool fMultiLine=false);
    QString HtmlEscape(const std::string& str, bool fMultiLine=false);

    /** Copy a field of the currently selected entry of a view to the clipboard. Does nothing if nothing
        is selected.
       @param[in] column  Data column to extract from the model
       @param[in] role    Data role to extract from the model
       @see  TransactionView::copyLabel, TransactionView::copyAmount, TransactionView::copyAddress
     */
    void copyEntryData(QAbstractItemView *view, int column, int role=Qt::EditRole);

    // Determine whether a widget is hidden behind other windows
    bool isObscured(QWidget *w);

} // namespace GUIUtil

#endif // GUIUTIL_H
