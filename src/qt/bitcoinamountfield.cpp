// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bitcoinamountfield.h"

#include "bitcoinunits.h"
#include "guiconstants.h"
#include "qvaluecombobox.h"

#include <QApplication>
#include <QDoubleSpinBox>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <qmath.h> // for qPow()

#include "tonalutils.h"

BitcoinAmountSpinBox::BitcoinAmountSpinBox(QWidget *parent)
 : QDoubleSpinBox(parent), currentUnit(-1)
{
    setLocale(QLocale::c());
    setDecimals(8);
    installEventFilter(parent);
    setMaximumWidth(170);
    setMaximum(21e14);
}

QValidator::State BitcoinAmountSpinBox::validate(QString&text, int&pos) const
{
    switch (currentNumsys) {
    default:
    case BitcoinUnits::BTC:
        return QDoubleSpinBox::validate(text, pos);
    case BitcoinUnits::TBC:
        return TonalUtils::validate(text, pos);
    }
}

QString BitcoinAmountSpinBox::textFromValue(double value) const
{
    return BitcoinUnits::format(currentUnit, value);
}

double BitcoinAmountSpinBox::valueFromText(const QString&text) const
{
    qint64 val;
    BitcoinUnits::parse(currentUnit, text, &val);
    return val;
}

void BitcoinAmountSpinBox::setUnit(int unit)
{
    currentUnit = unit;
    currentNumsys = BitcoinUnits::numsys(unit);
    qint64 factor = BitcoinUnits::factor(unit);
    switch (currentNumsys) {
    default:
    case BitcoinUnits::BTC:
        if (currentUnit == BitcoinUnits::uBTC)
            setSingleStep(0.01 * factor);
        else
            setSingleStep(0.001 * factor);
        break;
    case BitcoinUnits::TBC:
        setSingleStep(factor / 0x400);
    }
}


BitcoinAmountField::BitcoinAmountField(QWidget *parent) :
    QWidget(parent),
    amount(0),
    currentUnit(-1),
    nSingleStep(0)
{
    amount = new BitcoinAmountSpinBox(this);

    QHBoxLayout *layout = new QHBoxLayout(this);
    layout->addWidget(amount);
    unit = new QValueComboBox(this);
    unit->setModel(new BitcoinUnits(this));
    layout->addWidget(unit);
    layout->addStretch(1);
    layout->setContentsMargins(0,0,0,0);

    setLayout(layout);

    setFocusPolicy(Qt::TabFocus);
    setFocusProxy(amount);

    // If one if the widgets changes, the combined content changes as well
    connect(amount, SIGNAL(valueChanged(QString)), this, SIGNAL(textChanged()));
    connect(unit, SIGNAL(currentIndexChanged(int)), this, SLOT(unitChanged(int)));

    // Set default based on configuration
    unitChanged(unit->currentIndex());
}

void BitcoinAmountField::setText(const QString &text)
{
    if (text.isEmpty())
        amount->clear();
    else
        amount->setValue(amount->valueFromText(text));
}

void BitcoinAmountField::clear()
{
    amount->clear();
    unit->setCurrentIndex(0);
}

bool BitcoinAmountField::_is_valid() const
{
    if (amount->value() == 0.0)
        return false;
    if (amount->value() > BitcoinUnits::maxAmount(BitcoinUnits::uBTC))
        return false;
    return true;
}

bool BitcoinAmountField::validate()
{
    bool valid = _is_valid();
    setValid(valid);

    return valid;
}

void BitcoinAmountField::setValid(bool valid)
{
    if (valid)
        amount->setStyleSheet("");
    else
        amount->setStyleSheet(STYLE_INVALID);
}

QString BitcoinAmountField::text() const
{
    if (amount->text().isEmpty())
        return QString();
    else
        return amount->text();
}

bool BitcoinAmountField::eventFilter(QObject *object, QEvent *event)
{
    if (event->type() == QEvent::FocusIn)
    {
        // Clear invalid flag on focus
        setValid(true);
    }
    else if (event->type() == QEvent::KeyPress || event->type() == QEvent::KeyRelease)
    {
        QKeyEvent *keyEvent = static_cast<QKeyEvent *>(event);
        if (keyEvent->key() == Qt::Key_Comma)
        {
            // Translate a comma into a period
            QKeyEvent periodKeyEvent(event->type(), Qt::Key_Period, keyEvent->modifiers(), ".", keyEvent->isAutoRepeat(), keyEvent->count());
            QApplication::sendEvent(object, &periodKeyEvent);
            return true;
        }
    }
    return QWidget::eventFilter(object, event);
}

QWidget *BitcoinAmountField::setupTabChain(QWidget *prev)
{
    QWidget::setTabOrder(prev, amount);
    QWidget::setTabOrder(amount, unit);
    return unit;
}

qint64 BitcoinAmountField::value(bool *valid_out) const
{
    qint64 val_out = amount->value();
    bool valid = _is_valid();
    if (valid_out)
    {
        *valid_out = valid;
    }
    return val_out;
}

void BitcoinAmountField::setValue(qint64 value)
{
    amount->setValue(value);
}

void BitcoinAmountField::setReadOnly(bool fReadOnly)
{
    amount->setReadOnly(fReadOnly);
    unit->setEnabled(!fReadOnly);
}

void BitcoinAmountField::unitChanged(int idx)
{
    // Use description tooltip for current unit for the combobox
    unit->setToolTip(unit->itemData(idx, Qt::ToolTipRole).toString());

    // Determine new unit ID
    int newUnit = unit->itemData(idx, BitcoinUnits::UnitRole).toInt();

    // Parse current value and convert to new unit
    bool valid = false;
    qint64 currentValue = value(&valid);

    amount->setUnit(newUnit);
    currentUnit = newUnit;

    qint64 nSS = nSingleStep;
    if (!nSS)
    {
        int numsys = BitcoinUnits::numsys(newUnit);
        switch (numsys)
        {
            case BitcoinUnits::BTC:
                nSS = 100000;
                break;
            case BitcoinUnits::TBC:
                nSS = 0x10000;
                break;
        }
    }
    amount->setSingleStep(nSS);

    if (valid)
    {
        // If value was valid, re-place it in the widget with the new unit
        setValue(currentValue);
    }
    else
    {
        // If current value is invalid, just clear field
        setText("");
    }
    setValid(true);
}

void BitcoinAmountField::setDisplayUnit(int newUnit)
{
    unit->setValue(newUnit);
}

void BitcoinAmountField::setSingleStep(qint64 step)
{
    nSingleStep = step;
    unitChanged(unit->currentIndex());
}
