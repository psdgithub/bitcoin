#ifndef QTIPCSERVER_H
#define QTIPCSERVER_H

// Define Bitcoin-Qt message queue name
#define BITCOINURI_QUEUE_NAME "BitcoinURI"

void ipcThread(void* pArg);
void ipcThread2(void* pArg);
void ipcInit();

#endif // QTIPCSERVER_H
