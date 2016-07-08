QT += core
QT -= gui

CONFIG += c++11

TARGET = hw_pcap
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp

CONFIG += static-libgcc

INCLUDEPATH += "C:\Program Files (x86)\WinPcap\WpdPack\Include"
LIBS += -L "C:\Program Files (x86)\WinPcap\WpdPack\Lib" -lwpcap -lpacket -lws2_32
DEFINES += WPCAP
DEFINES += HAVE_REMOTE
