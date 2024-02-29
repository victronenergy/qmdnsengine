#include "mdnsscanner.h"

using namespace QMdnsEngine;

static const char TAG[] = "[MDNSSC]";

MdnsScanner::MdnsScanner(QByteArray serviceName, QObject *parent)
	: QObject{parent}
{
	setServiceName(serviceName);
	init();
}

MdnsScanner::MdnsScanner(QList<QByteArray> serviceList, QObject *parent)
	: QObject{parent}
{
	setServiceList(serviceList);
	init();
}

void MdnsScanner::init()
{
	qRegisterMetaType<QMdnsEngine::Message>();

	queryTimer.setInterval(rescanPeriod * 1000);
	queryTimer.setSingleShot(true);

	checkDevicesTimer.setInterval(checkDevicesPeriod * 1000);
	checkDevicesTimer.setSingleShot(false);

	connect(&queryTimer			, &QTimer::timeout, this, &MdnsScanner::onQueryTimeout       , Qt::QueuedConnection);
	connect(&checkDevicesTimer	, &QTimer::timeout, this, &MdnsScanner::onCheckDevicesTimeout, Qt::QueuedConnection);
}

MdnsScanner::~MdnsScanner(){
	qDebug() << TAG << __PRETTY_FUNCTION__;
	stopScan();
}

void MdnsScanner::cleanDeviceList()
{
	foreach (auto deviceName, deviceList.values()) {
		removeDevice(deviceName);
	}
}

void MdnsScanner::resetDeviceTimeouts()
{
	foreach (auto deviceName, deviceLastResponse.keys()) {
		deviceLastResponse.insert(deviceName,QTime::currentTime());
	}
}

void MdnsScanner::startScan()
{
	qDebug() << TAG << __PRETTY_FUNCTION__;
	if (server == nullptr) {
		server  = new QMdnsEngine::Server();
		connect(server, &QMdnsEngine::Server::messageReceived, this, &MdnsScanner::onMessageReceived);
	}
	onQueryTimeout();
	checkDevicesTimer.start();
}

void MdnsScanner::stopScan()
{
	queryTimer.stop();
	checkDevicesTimer.stop();
	// TODO: Try the next to remove server
	// disconnect(server, &QMdnsEngine::Server::messageReceived, this, &MdnsScanner::onMessageReceived);
	// connect(this,&QObject::destroyed,server,&QObject::deleteLater,Qt::QueuedConnection);
}

void MdnsScanner::setServiceName(QByteArray serviceName)
{
	serviceNamesArray.clear();
	serviceNamesArray.insert(serviceName);
}

void MdnsScanner::addServiceName(QByteArray serviceName)
{
	serviceNamesArray.insert(serviceName);
}

void MdnsScanner::setServiceList(QList<QByteArray> serviceList)
{
	serviceNamesArray.clear();
	foreach(auto service, serviceList)
	{
		serviceNamesArray.insert(service);
	}
}

void MdnsScanner::setMessageFilterContent(QByteArray content)
{
	messageFilterContent = content;
}

bool MdnsScanner::checkMessageRecordsContent(QList<QMdnsEngine::Record> recordList)
{
	bool validData = false;
	for (const Record &record : recordList) {
		switch (record.type()) {
		case TXT:
			if (record.attributes().size()) {
				for (auto [attr,value]: record.attributes().asKeyValueRange()) {
					if (attr.contains(messageFilterContent)) {
						validData = true;
					}
				}
			}
			break;
		default:
			break;
		}
	}
	return validData;
}

void MdnsScanner::onMessageReceived(const Message &message)
{
	if (!message.isResponse()) {
		return;
	}

	if (!queryTimer.isActive()) {
		// The scanner has been stopped
		return;
	}

	const bool any = serviceNamesArray.contains(MdnsBrowseType);

	const auto records = message.records();

	if (!checkMessageRecordsContent(records)) {
		return;
	}

#if DEBUG_MDNSSCANNER_MESSAGES_DEBUG > 1
	printDecodedMessageContent(message);
#endif

	// Collect data from all records
	QByteArray hostname;
	QByteArray address;
	QByteArray serialNumber;
	QSet<QByteArray> reportedServicesList;
	QHash<QByteArray, QMap<QByteArray, QByteArray>> servicePropertiesList;
	QHash<QByteArray, QByteArray> txtRecords;

	for (const Record &record : records) {
		QByteArray fqdn;			// Fully Qualified Domain Name:
		QByteArray serviceName;
		QMap<QByteArray, QByteArray> serviceProperties;
		int index;
		switch (record.type()) {
		case SRV:
			fqdn  = record.name();
			index = fqdn.indexOf('.');
			hostname    = fqdn.left(index);
			serviceName = fqdn.mid(index + 1);
			if (any || serviceNamesArray.contains(serviceName)) {
				serviceProperties = servicePropertiesList.value(serviceName, QMap<QByteArray, QByteArray>());
				serviceProperties.insert("port", QByteArray::number(record.port()));
				servicePropertiesList.insert(serviceName, serviceProperties);
			}
			break;
		case TXT:
			for (auto [key,value]: record.attributes().asKeyValueRange()) {
				txtRecords.insert(key,value);
			}
			break;
		case A:
		case AAAA:
			address = record.address().toString().toUtf8();
			break;
		case PTR:
			fqdn = record.name();
			reportedServicesList.insert(fqdn);
		default:
			break;
		}
	}
	serialNumber = txtRecords.value("serial", QByteArray());

	bool thereIsEnoughData = true;
	thereIsEnoughData &= !hostname.isEmpty();
	thereIsEnoughData &= !address.isEmpty();
	thereIsEnoughData &= !serialNumber.isEmpty();
	if (!thereIsEnoughData) {
		return;
	}

	// Build a DeviceData for every service discovered
	foreach (auto serviceName, reportedServicesList) {
		bool thereIsEnoughData = true;
		thereIsEnoughData &= servicePropertiesList.keys().contains(serviceName);
		if (thereIsEnoughData) {
			DeviceData deviceData;
			deviceData.insert("hostname",hostname);
			deviceData.insert("address" ,address);
			deviceData.insert("service" ,serviceName);
			for (auto [serviceProperty, value]: servicePropertiesList.value(serviceName).asKeyValueRange()) {
				deviceData.insert(serviceProperty,value);
			}
			for (auto [property, value]: txtRecords.asKeyValueRange()) {
				deviceData.insert(property, txtRecords.value(property));
			}
			printDecodedDeviceData(deviceData);
			deviceList.insert(serialNumber);
			deviceLastResponse.insert(serialNumber ,QTime::currentTime());
			QSet<QByteArray> serviceList = servicesOfDevices.value(serialNumber, QSet<QByteArray>());
			serviceList.insert(serviceName);
			servicesOfDevices.insert(serialNumber,serviceList);
			if (!deviceList.contains(serialNumber)) {
				emit deviceDiscovered(deviceData);
			} else {
				emit deviceUpdated(deviceData);
			}
		}
	}
}

void MdnsScanner::onQueryTimeout()
{
	foreach (auto serviceName, serviceNamesArray) {
		Query query;
		query.setName(serviceName);
		query.setType(PTR);
		Message message;
		message.addQuery(query);
		message.setTransactionId(++transactionId);
		server->sendMessageToAll(message);
	}
	queryTimer.start();
}

void MdnsScanner::onCheckDevicesTimeout()
{
	QSet<QByteArray> servicesOfTheDevice;
	foreach (auto deviceName, deviceLastResponse.keys()) {
		if (deviceLastResponse.value(deviceName).addSecs(timeToDisconnect) < QTime::currentTime()) {
			servicesOfTheDevice = servicesOfDevices.value(deviceName);
			qDebug() << TAG << "Device" << deviceName << "does not respond anymore | Attached services:" << servicesOfTheDevice;
			removeDevice(deviceName);
		}
	}
}

void MdnsScanner::removeDevice(QByteArray deviceName)
{
	DeviceData deviceData;
	deviceData.insert("serial",deviceName);
	deviceList.remove(deviceName);
	deviceLastResponse.remove(deviceName);
	servicesOfDevices.remove(deviceName);
	emit deviceRemoved(deviceData);
}

void MdnsScanner::printDecodedMessageContent(Message message)
{
	const auto records = message.records();
	QString debugTxt;
	debugTxt += "Message received from " + message.address().toString();
	debugTxt += " | Transaction ID " + QString::number(message.transactionId());
	debugTxt += " | Full message records details";
	foreach (Record record, records) {
		debugTxt.append(QString(QChar::LineSeparator));
		debugTxt.append("    ");
		// Record type
		debugTxt.append(QMdnsEngine::typeName(record.type()).leftJustified(6));
		// Record name (Full Qualified Domain Name)
		debugTxt.append(record.name().leftJustified(65));
		// Extra data
		debugTxt.append(" : ");
		// Record address data
		if (record.type() == A || record.type() == AAAA) {
			debugTxt.append("Address ");
			debugTxt.append(record.address().toString().leftJustified(16));
		}
		// Service Port
		if (record.type() == SRV ) {
			debugTxt.append("Port ");
			debugTxt.append(QString::number(record.port()).leftJustified(6));
		}
		// Attributes
		if (record.attributes().size()) {
			debugTxt.append("Attributes(").append(QString::number(record.attributes().size())).append(")    ");
			for (auto [attr,value]: record.attributes().asKeyValueRange()) {
				debugTxt.append(" <").append(attr).append(" ").append(value).append(">");
			}
		}
	}
	qDebug() << TAG << debugTxt;
}

void MdnsScanner::printDecodedDeviceData(DeviceData deviceData)
{
	QByteArray serialNumber = deviceData.value("serial");
	QByteArray serviceName  = deviceData.value("service");
	QString debugTxt;
	if (!deviceList.contains(serialNumber)) {
		debugTxt += "New device discovered";
	} else {
		debugTxt += "Already known device";
	}
	debugTxt += " | Serial " + serialNumber + " | Service " + serviceName;
#if DEBUG_MDNSSCANNER_MESSAGES_DEBUG
	debugTxt += QString(QChar::LineSeparator);
	debugTxt += QString("    Decoded device data");
	debugTxt += QString(QChar::LineSeparator);
	for (auto [key,value]: deviceData.asKeyValueRange()) {
		debugTxt += QString("        ") + QString(key.leftJustified(12)) + QString(value) + QString(QChar::LineSeparator);
	}
	debugTxt += "    Total services discovered for this device: ";
	foreach (QByteArray serviceName, servicesOfDevices.value(serialNumber).values())
	{
		debugTxt += QString(serviceName) + QString("; ");
	}
#endif
	qDebug() << TAG << debugTxt;
}
