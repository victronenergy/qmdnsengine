#ifndef MDNSSCANNER_H
#define MDNSSCANNER_H

#include <QtCore>
#include <QObject>
#include <QTimer>
#include <QMap>
#include <QTime>

#include <server.h>
#include <dns.h>
#include <mdns.h>
#include <message.h>
#include <query.h>
#include <record.h>

#ifndef DEBUG_MDNSSCANNER_MESSAGES_DEBUG
#define DEBUG_MDNSSCANNER_MESSAGES_DEBUG 0
#endif

class MdnsScanner : public QObject
{
	Q_OBJECT

public:
	explicit MdnsScanner(QByteArray serviceName = QMdnsEngine::MdnsBrowseType, QObject *parent = nullptr);
	explicit MdnsScanner(QList<QByteArray> servicesList, QObject *parent = nullptr);

	~MdnsScanner();

	void setServiceName(QByteArray serviceName);
	void addServiceName(QByteArray serviceName);
	void setServiceList(QList<QByteArray> servicesList);

	void setRescanPeriod(int period)	{ rescanPeriod = period; };
	void setTimeToDisconnect(int time)	{ timeToDisconnect = time; }

	void setMessageFilterContent(QByteArray content);

	typedef QMap<QByteArray,QByteArray> DeviceData;

	void cleanDeviceList();
	void resetDeviceTimeouts();

public slots:
	void startScan();
	void stopScan();

signals:
	void deviceDiscovered(DeviceData deviceData);
	void deviceUpdated(DeviceData deviceData);
	void deviceRemoved(DeviceData deviceData);

private:
	void init();

	int rescanPeriod		= 4;
	int timeToDisconnect	= 10;
	int checkDevicesPeriod	= 1;

	QSet<QByteArray> serviceNamesArray;

	QSet<QByteArray> deviceList;
	QHash<QByteArray,QTime> deviceLastResponse;
	QHash<QByteArray,QSet<QByteArray>> servicesOfDevices;

	QMdnsEngine::Server * server = nullptr;
	QTimer queryTimer;
	QTimer checkDevicesTimer;

	QByteArray messageFilterContent = QByteArray("victron");

	bool checkMessageRecordsContent(QList<QMdnsEngine::Record> recordList);

private slots:
	void onMessageReceived(const QMdnsEngine::Message &message);

	void onQueryTimeout();
	void onCheckDevicesTimeout();
	void removeDevice(QByteArray deviceName);
};

Q_DECLARE_METATYPE(MdnsScanner::DeviceData)
Q_DECLARE_METATYPE(QMdnsEngine::Message)

#endif // MDNSSCANNER_H
