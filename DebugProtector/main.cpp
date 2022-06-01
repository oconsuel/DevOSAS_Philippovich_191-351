#include "mainwindow.h"
#include "windows.h"
#include <QApplication>
#include "QProcess"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    DWORD pid = (DWORD) atoi(argv[1]);
    bool isAttached = DebugActiveProcess(pid);
    if(!isAttached){
        DWORD lastError = GetLastError();
        qDebug() << lastError;
        return lastError;
    }
    DEBUG_EVENT DbgEvent;
    while(1){
        WaitForDebugEvent(&DbgEvent, INFINITE);
        ContinueDebugEvent(DbgEvent.dwProcessId, DbgEvent.dwThreadId, DBG_CONTINUE);
        if(pid==0){


        }
        //TODO WAIT
    }
}
