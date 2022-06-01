#include "dbmodel.h"

#include <iostream>

#include "QDebug"
#include "QFile"
#include "QJsonArray"
#include "QJsonDocument"
#include "QJsonObject"
#include "crypt.h"

DBModel::DBModel(const QString key) {
  this->key = key;
  this->file = readFile();
  this->json = readJson(key);
}
const QString DBModel::kFileName = "encoded.json";

QJsonArray DBModel::readJson(QString key) {
  auto decodedFile = Crypt::decrypt(this->file, key, key);

  auto start = decodedFile.indexOf("\n");
  auto jsonStr = decodedFile.sliced(start, decodedFile.length() - start);

  QJsonDocument d = QJsonDocument::fromJson(jsonStr.toUtf8());
  QJsonArray json = d.QJsonDocument::array();
  qDebug() << d;
  return json;
}

QByteArray DBModel::readFile() {
  QFile file(DBModel::kFileName);

  file.open(QIODevice::ReadWrite | QIODevice::Text);
  auto readedFile = file.readAll();

  file.close();
  return readedFile;
}

void DBModel::writeFile() {
  QJsonDocument doc(this->json);
  QString strJson(doc.toJson(QJsonDocument::Compact));

  QFile file(DBModel::kFileName);
  file.open(QIODevice::ReadWrite | QIODevice::Text);
  auto encodedText = Crypt::encrypt((this->key + "\n" + strJson).toUtf8(),
                                    this->key, this->key);
  file.write(encodedText);

  file.close();
  file.open(QIODevice::ReadOnly | QIODevice::Text);
  this->file = file.readAll();
}
void DBModel::writeRowToJSON(DBModel::Row row) {
  QJsonObject obj;
  obj[DBModel::fields.login] = row.login;
  obj[DBModel::fields.pass] = row.pass;
  obj[DBModel::fields.url] = row.url;

  this->json.append(obj);
  this->writeFile();
}

DBModel::Row DBModel::getRow(int index) {
  QJsonObject jsonRow = json[index].toObject();
  DBModel::Row row = {jsonRow["url"].toString(), jsonRow["login"].toString(),
                      jsonRow["pass"].toString()};
  return row;
}

DBModel::Row DBModel::encrypt(DBModel::Row row) {
  auto login = row.login;
  auto eLogin = Crypt::encrypt((login).toUtf8(), this->key, this->key);

  auto pass = row.pass;
  auto ePass = Crypt::encrypt((pass).toUtf8(), this->key, this->key);

  Row res = {row.url, eLogin, ePass};
  return res;
}

DBModel::Row DBModel::decrypt(DBModel::Row row) {
  auto login = row.login;
  auto plainLogin = Crypt::decrypt((login).toUtf8(), this->key, this->key);

  auto pass = row.pass;
  auto plainPass = Crypt::decrypt((pass).toUtf8(), this->key, this->key);

  Row res = {row.url, plainLogin, plainPass};
  return res;
}
