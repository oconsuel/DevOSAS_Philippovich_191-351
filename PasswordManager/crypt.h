#ifndef CRYPT_H
#define CRYPT_H
#include "QByteArray"
#include "QString"
#include "qaesencryption.h"

class Crypt {
 public:
  Crypt();
  static QByteArray getKey(QString plainKey);
  static QByteArray getIV(QString plainIV);
  static QByteArray encrypt(QByteArray text, QString key, QString iv);
  static QString decrypt(QByteArray text, QString key, QString iv);

  static QAESEncryption encrypter;
};

#endif  // CRYPT_H
