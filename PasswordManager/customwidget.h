#ifndef CUSTOMWIDGET_H
#define CUSTOMWIDGET_H
#include <QWidget>

#include "dbmodel.h"

namespace Ui {
class CustomWidget;
}

class CustomWidget : public QWidget {
  Q_OBJECT

 public:
  explicit CustomWidget(QString pass, QWidget *parent = nullptr);
  ~CustomWidget();
  bool show = false;
  QString pass;

  void setText(const DBModel::Row row);
  DBModel::Row getRow();

 signals:
  void sendRemoveItem(const QString &text);

 private slots:
  void on_toolButton_clicked();

 private:
  Ui::CustomWidget *ui;
};

#endif  // CUSTOMWIDGET_H
