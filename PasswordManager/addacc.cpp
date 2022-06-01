#include "addacc.h"

#include "dbmodel.h"
#include "ui_addacc.h"

addAcc::addAcc(QWidget *parent) : QDialog(parent), ui(new Ui::addAcc) {
  ui->setupUi(this);
}

addAcc::~addAcc() { delete ui; }
DBModel::Row addAcc::getInputValues() const {
  QString Url = ui->inputUrl->text();
  QString Login = ui->inputLogin->text();
  QString Pass = ui->inputPass->text();
  DBModel::Row row = {Url, Login, Pass};

  return row;
}
