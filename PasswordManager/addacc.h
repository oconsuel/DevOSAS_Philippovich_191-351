#ifndef ADDACC_H
#define ADDACC_H
#include <QDialog>

#include "QAbstractButton"
#include "dbmodel.h"

namespace Ui {
class addAcc;
}

class addAcc : public QDialog {
  Q_OBJECT

 public:
  explicit addAcc(QWidget *parent = nullptr);
  ~addAcc();
  DBModel::Row getInputValues() const;


 private:
  Ui::addAcc *ui;
};

#endif  // ADDACC_H
