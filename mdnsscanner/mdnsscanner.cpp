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
	QString debugTxt;
	foreach(Record record, records){
		debugTxt.append(QString(QChar::LineSeparator)).append("        ");
		debugTxt.append(QMdnsEngine::typeName(record.type()).leftJustified(6));
		debugTxt.append(record.name().leftJustified(48));
		if (record.attributes().size()) {
			debugTxt.append("#Attr(").append(QString::number(record.attributes().size())).append(") ");
			for (auto [attr,value]: record.attributes().asKeyValueRange()) {
				debugTxt.append(" <").append(attr).append(" ").append(value).append("> ");
			}
		}
	}
	qDebug() << TAG << __FUNCTION__ << debugTxt;
#endif

	DeviceData device;
	QByteArray fqdn;			// Fully Qualified Domain Name:
	QByteArray hostname;
	QByteArray serviceType;
	int index;
	bool thereIsEnoughData = false;
	device.insert("address",message.address().toString().toUtf8());
	for (const Record &record : records) {
		switch (record.type()) {
		case SRV:
			fqdn  = record.name();
			index = fqdn.indexOf('.');
			hostname    = fqdn.left(index);
			serviceType = fqdn.mid(index + 1);
			if (any || serviceNamesArray.contains(serviceType)) {
				thereIsEnoughData = true;
				device.insert("service",serviceType);
				device.insert("port"   ,QByteArray::number(record.port()));
			}
			break;
		case TXT:
			for (auto [key,value]: record.attributes().asKeyValueRange()) {
				device.insert(key,value);
			}
			break;
		case A:
		case AAAA:
		case PTR:
		default:
			break;
		}
	}
	QByteArray serialNumber = device.value("serial",QByteArray());
	thereIsEnoughData &= !serialNumber.isEmpty();
	if (!thereIsEnoughData) {
		return;
	}

	QByteArray deviceName = serialNumber;
	QSet<QByteArray> serviceList;
	if (!deviceList.contains(deviceName)) {
		qDebug() << TAG << "New device discovered:" << deviceName << "  | Service:" << serviceType;
		deviceList.insert(deviceName);
		deviceLastResponse.insert(deviceName ,QTime::currentTime());
		serviceList.insert(serviceType);
		servicesOfDevices.insert(deviceName,serviceList);
		emit deviceDiscovered(device);
	} else {
#if DEBUG_MDNSSCANNER_MESSAGES_DEBUG
		qDebug() << TAG << "Already known device response:" << deviceName << "  | Service:" << serviceType;
#endif
		deviceLastResponse.insert(deviceName,QTime::currentTime());
		serviceList = servicesOfDevices.value(deviceName);
		serviceList.insert(serviceType);
		servicesOfDevices.insert(deviceName,serviceList);
		emit deviceUpdated(device);
	}

#if DEBUG_MDNSSCANNER_MESSAGES_DEBUG
	QString debugTxtB = QString("| Decoded device data") + QString(QChar::LineSeparator);
	debugTxtB += QString("    ") + QString("Device ") + QString(deviceName) + QString(QChar::LineSeparator);
	for (auto [key,value]: device.asKeyValueRange()) {
		debugTxtB += QString("        ") + QString(key.leftJustified(12)) + QString(value) + QString(QChar::LineSeparator);
	}
	debugTxtB += "    Total services discovered for the device: ";
	foreach (QByteArray serviceName, servicesOfDevices.value(deviceName).values())
	{
		debugTxtB += QString(serviceName) + QString("; ");
	}
	qDebug() << TAG << __FUNCTION__ << debugTxtB;
#endif
}

void MdnsScanner::onQueryTimeout()
{
	foreach (auto serviceName, serviceNamesArray) {
		Query query;
		query.setName(serviceName);
		query.setType(PTR);
		Message message;
		message.addQuery(query);
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
