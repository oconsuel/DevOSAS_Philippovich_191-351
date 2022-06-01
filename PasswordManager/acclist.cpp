#include "acclist.h"

#include <QListWidget>
#include <QListWidgetItem>

#include "QFile"
#include "QJsonArray"
#include "QJsonDocument"
#include "QJsonObject"
#include "addacc.h"
#include "customwidget.h"
#include "dbmodel.h"
#include "qaesencryption.h"
#include "ui_acclist.h"

AccList::AccList(QString key, QWidget *parent)  // передаем ключ в это окно
    : QDialog(parent), ui(new Ui::AccList) {
  ui->setupUi(this);
  this->key = key;
  qInfo() << "key in acclist" << this->key;
  DBModel db(this->key);
  auto json = db.json;
  for (int i = 0; i < json.size(); ++i) {
    this->addRow(db.getRow(i));
  }
}

AccList::~AccList() { delete ui; }

void AccList::showItem(const QString &text) {
  //    for (int i = 0; i < ui->listWidget->count(); ++i) {

  //        auto item = ui->listWidget->item(i);
  //        auto itemWidget =
  //        dynamic_cast<CustomWidget*>(ui->listWidget->itemWidget(item)); if
  //        (itemWidget->getRow() == text){
  //            delete item;
  //            break;
  //        }
  //    }
}

void AccList::addRow(const DBModel::Row row) {  // добавление записей в GUI
  auto item = new QListWidgetItem();
  auto widget = new CustomWidget(key, this);
  widget->setText(row);
  item->setSizeHint(widget->sizeHint());
  ui->listWidget->addItem(item);
  ui->listWidget->setItemWidget(item, widget);
}

void AccList::on_addAccBtn_clicked() {  // добавление записей в json
  addAcc NewWindow;
  NewWindow.setModal(true);
  if (NewWindow.exec() == QDialog::Accepted) {
    auto row = NewWindow.getInputValues();

    DBModel db(this->key);
    auto eRow = db.encrypt(row);
    this->addRow(eRow);

    db.writeRowToJSON(eRow);
  }
}

void AccList::on_searchButton_clicked() {
  auto searchText = ui->searchInput->text();

  auto listWidget = this->ui->listWidget;

  for (auto i = 0; i < listWidget->count(); i++) {
    auto item = listWidget->item(i);
    auto itemWidget =
        dynamic_cast<CustomWidget *>(ui->listWidget->itemWidget(item));
    if (itemWidget->getRow().url.startsWith(searchText)) {
      item->setHidden(false);
    } else {
      item->setHidden(true);
    }
  }
}
