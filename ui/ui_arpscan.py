# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'arpscan.ui'
##
## Created by: Qt User Interface Compiler version 6.7.3
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QGroupBox,
    QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QPushButton, QSizePolicy, QVBoxLayout, QWidget)

class Ui_DeviceDiscovery(object):
    def setupUi(self, DeviceDiscovery):
        if not DeviceDiscovery.objectName():
            DeviceDiscovery.setObjectName(u"DeviceDiscovery")
        DeviceDiscovery.resize(658, 694)
        self.verticalLayout = QVBoxLayout(DeviceDiscovery)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.label = QLabel(DeviceDiscovery)
        self.label.setObjectName(u"label")

        self.verticalLayout.addWidget(self.label)

        self.devices = QListWidget(DeviceDiscovery)
        self.devices.setObjectName(u"devices")

        self.verticalLayout.addWidget(self.devices)

        self.label_2 = QLabel(DeviceDiscovery)
        self.label_2.setObjectName(u"label_2")

        self.verticalLayout.addWidget(self.label_2)

        self.responses = QListWidget(DeviceDiscovery)
        self.responses.setObjectName(u"responses")

        self.verticalLayout.addWidget(self.responses)

        self.groupBox = QGroupBox(DeviceDiscovery)
        self.groupBox.setObjectName(u"groupBox")
        self.horizontalLayout_2 = QHBoxLayout(self.groupBox)
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.power = QCheckBox(self.groupBox)
        self.power.setObjectName(u"power")
        self.power.setChecked(True)

        self.horizontalLayout_2.addWidget(self.power)

        self.discoverable = QCheckBox(self.groupBox)
        self.discoverable.setObjectName(u"discoverable")
        self.discoverable.setChecked(True)

        self.horizontalLayout_2.addWidget(self.discoverable)


        self.verticalLayout.addWidget(self.groupBox)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.scan = QPushButton(DeviceDiscovery)
        self.scan.setObjectName(u"scan")

        self.horizontalLayout.addWidget(self.scan)

        self.clear = QPushButton(DeviceDiscovery)
        self.clear.setObjectName(u"clear")

        self.horizontalLayout.addWidget(self.clear)

        self.quit = QPushButton(DeviceDiscovery)
        self.quit.setObjectName(u"quit")

        self.horizontalLayout.addWidget(self.quit)


        self.verticalLayout.addLayout(self.horizontalLayout)


        self.retranslateUi(DeviceDiscovery)
        self.quit.clicked.connect(DeviceDiscovery.accept)
        self.clear.clicked.connect(self.devices.clear)

        QMetaObject.connectSlotsByName(DeviceDiscovery)
    # setupUi

    def retranslateUi(self, DeviceDiscovery):
        DeviceDiscovery.setWindowTitle(QCoreApplication.translate("DeviceDiscovery", u"Arp Scanner", None))
        self.label.setText(QCoreApplication.translate("DeviceDiscovery", u"Devices detected", None))
        self.label_2.setText(QCoreApplication.translate("DeviceDiscovery", u"ARP responses", None))
        self.groupBox.setTitle(QCoreApplication.translate("DeviceDiscovery", u"Local Device", None))
        self.power.setText(QCoreApplication.translate("DeviceDiscovery", u"Arp Scan Powered On", None))
        self.discoverable.setText(QCoreApplication.translate("DeviceDiscovery", u"Discoverable", None))
        self.scan.setText(QCoreApplication.translate("DeviceDiscovery", u"Scan", None))
        self.clear.setText(QCoreApplication.translate("DeviceDiscovery", u"Clear", None))
        self.quit.setText(QCoreApplication.translate("DeviceDiscovery", u"Quit", None))
    # retranslateUi

