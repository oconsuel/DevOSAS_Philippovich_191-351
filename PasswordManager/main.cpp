/// clang-format off

#include <windows.h>
#include <winbase.h>
// clang-format on

#include <Tlhelp32.h>
#include <process.h>
#include <stdio.h>
#include <string.h>

#include <QApplication>

#include "QCryptographicHash"
#include "QDebug"
#include "QMessageBox"
#include "QProcess"
#include "QString"
#include "mainwindow.h"
#include <QStyleFactory>

typedef unsigned long long QWORD;

int main(int argc, char *argv[]) {
  QApplication a(argc, argv);
  MainWindow w;
  w.show();

  qApp->setStyle(QStyleFactory::create("Fusion"));

  QPalette darkPalette;
  darkPalette.setColor(QPalette::Window, Qt::darkGreen);
  darkPalette.setColor(QPalette::WindowText, Qt::magenta);
  darkPalette.setColor(QPalette::Base, QColor(25,25,25));
  darkPalette.setColor(QPalette::AlternateBase, Qt::darkGreen);
  darkPalette.setColor(QPalette::ToolTipBase, Qt::magenta);
  darkPalette.setColor(QPalette::ToolTipText, Qt::magenta);
  darkPalette.setColor(QPalette::Text, Qt::magenta);
  darkPalette.setColor(QPalette::Button, Qt::darkGreen);
  darkPalette.setColor(QPalette::ButtonText, Qt::magenta);
  darkPalette.setColor(QPalette::BrightText, Qt::red);
  darkPalette.setColor(QPalette::Link, QColor(42, 130, 218));

  darkPalette.setColor(QPalette::Highlight, QColor(42, 130, 218));
  darkPalette.setColor(QPalette::HighlightedText, Qt::black);

  qApp->setPalette(darkPalette);

  qApp->setStyleSheet("QToolTip { color: #ffffff; background-color: #2a82da; border: 1px solid white; }");

  QProcess *satelliteProcess = new QProcess();
  int pid = QApplication::applicationPid();
  QStringList arguments = {QString::number(pid)};
  satelliteProcess->start("DebugProtector.exe", arguments);
  bool protectorStarted = satelliteProcess->waitForStarted(1000);

  // 1 Определение начала сегмента .text
  QWORD moduleBase = (QWORD)GetModuleHandleW(NULL); //начальный адрес приложенияв виртуальной памяти/
  QWORD text_segment_start = moduleBase + 0x1000; //адрессегмента .text/


  // 2 Определение длины сегмента .text
  PIMAGE_DOS_HEADER pIDH = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);
  PIMAGE_NT_HEADERS pINH = reinterpret_cast<PIMAGE_NT_HEADERS>(moduleBase+pIDH->e_lfanew);
  QWORD size_of_text = pINH->OptionalHeader.SizeOfCode;
  //размер сегмента .text

  // 3 Подсчет хэша и его шифрование
  QByteArray text_segment_contents = QByteArray((char*)text_segment_start,
  size_of_text); QByteArray hash = QCryptographicHash::hash((text_segment_contents),QCryptographicHash::Sha256).toBase64();
  qInfo() << "hash = " << hash;

  // 4 Сравнение хэша полученного на прошлых этапах с эталонным
  const QByteArray hash0_base64 = QByteArray("H6K4fFY1SWQ83dk4slE9xJvxYMIQSmJ6gtTsmPmJW9k=");
  bool checkresult =(hash==hash0_base64);

  // 5 Реакция на измененный хэш
  if(!checkresult){
    int result = QMessageBox::critical(nullptr,"Warning!","App has been patched");
    return -1, system("taskkill /im DebugProtector.exe /f");
  }
  return a.exec(), system("taskkill /im DebugProtector.exe /f");
}
