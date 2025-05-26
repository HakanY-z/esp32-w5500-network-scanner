// === ESP32 + W5500 Gelişmiş Ağ Tarayıcı v3 ===
// Özellikler: TCP & UDP port tarama, Banner Grabbing, ARP ile MAC tespiti, Web arayüzü ve WebSocket

#include <WiFi.h>
#include <WebServer.h>
#include <WebSocketsServer.h>
#include <SPI.h>
#include <Ethernet2.h>
#include <FS.h>
#include <SPIFFS.h>
#include <ArduinoJson.h>
#include "utility/w5500.h"
#include "utility/socket.h"

#define LED_PIN        2
#define CS_PIN         5
#define NUM_SCAN_TASKS 6
#define MACRAW_SOCKET  0

const char* ssid     = "ESP32_Scanner";
const char* password = "12345678";

WebServer        server(80);
WebSocketsServer webSocket(81);

byte     localMac[6]  = {0xDE,0xAD,0xBE,0xEF,0xFE,0xED};
IPAddress localIP, mySubnetMask, gatewayIP, dnsIP;

String scanResult = "";
bool   scanning   = false;
volatile int tasksCompleted = 0;
int    scannedIPs = 0;
SemaphoreHandle_t scanMutex;

struct ScanTaskParams { int startIndex, step; };

int tcpPorts[] = {80,443,22,445,3389,21,23,53,110,143,25};
int udpPorts[] = {53,123,161,1900};

// Tarama sonuçlarını önbelleğe almak için yapı
struct ScanResult {
  IPAddress ip;
  String mac;
  String ports;
  unsigned long timestamp;
};

#define MAX_CACHE_SIZE 50
#define CACHE_TIMEOUT 300000  // 5 dakika
ScanResult resultCache[MAX_CACHE_SIZE];
int cacheIndex = 0;

// Önbellekten sonuç kontrolü
String getCachedResult(IPAddress ip) {
  for(int i=0; i<MAX_CACHE_SIZE; i++) {
    if(resultCache[i].ip == ip && 
       (millis() - resultCache[i].timestamp) < CACHE_TIMEOUT) {
      return resultCache[i].mac + "\n" + resultCache[i].ports;
    }
  }
  return "";
}

// Önbelleğe sonuç ekleme
void cacheResult(IPAddress ip, String mac, String ports) {
  resultCache[cacheIndex].ip = ip;
  resultCache[cacheIndex].mac = mac;
  resultCache[cacheIndex].ports = ports;
  resultCache[cacheIndex].timestamp = millis();
  cacheIndex = (cacheIndex + 1) % MAX_CACHE_SIZE;
}

// TCP bağlantı timeout ile kontrol
bool connectWithTimeout(EthernetClient& client, IPAddress ip, int port, int timeout=1000) {
  unsigned long start = millis();
  client.connect(ip, port);
  while(!client.connected() && (millis() - start) < timeout) {
    delay(1);
  }
  return client.connected();
}

// İstek çerçevesini raw gönder
void sendARPRequest(IPAddress target) {
  uint8_t frame[42];
  memset(frame,0xFF,6);
  memcpy(frame+6,localMac,6);
  frame[12]=0x08; frame[13]=0x06;              // EtherType = ARP
  frame[14]=0; frame[15]=1;                     // HTYPE=Ethernet
  frame[16]=0x08; frame[17]=0;                  // PTYPE=IPv4
  frame[18]=6; frame[19]=4;                     // HLEN=6, PLEN=4
  frame[20]=0; frame[21]=1;                     // OPER=1 (request)
  memcpy(frame+22,localMac,6);                  // Sender MAC
  frame[28]=localIP[0]; frame[29]=localIP[1];  // Sender IP
  frame[30]=localIP[2]; frame[31]=localIP[3];
  memset(frame+32,0,6);                         // Target MAC = 0
  frame[38]=target[0]; frame[39]=target[1];     // Target IP
  frame[40]=target[2]; frame[41]=target[3];

  uint16_t free = w5500.getTXFreeSize(MACRAW_SOCKET);
  if (free >= sizeof(frame)) {
    w5500.send_data_processing(MACRAW_SOCKET, frame, sizeof(frame));
    w5500.execCmdSn(MACRAW_SOCKET, Sock_SEND);
  }
}

// ARP ile MAC tespiti
String getMacForIP(IPAddress target, uint16_t timeout=300) {
  sendARPRequest(target);
  uint32_t deadline = millis() + timeout;
  String mac = "";
  while (millis() < deadline) {
    uint16_t len = w5500.getRXReceivedSize(MACRAW_SOCKET);
    if (len >= 44) {
      uint8_t buf[256];
      uint16_t rd = min<uint16_t>(len, sizeof(buf));
      recv(MACRAW_SOCKET, buf, rd);
      uint8_t* f = buf + 2;
      uint16_t et = (f[12]<<8)|f[13], op = (f[20]<<8)|f[21];
      if (et==0x0806 && op==2) {
        char tmp[18];
        sprintf(tmp, "%02X:%02X:%02X:%02X:%02X:%02X",
                f[6],f[7],f[8],f[9],f[10],f[11]);
        mac = String(tmp);
        break;
      }
    } else if (len) {
      uint8_t junk[64];
      recv(MACRAW_SOCKET, junk, min<uint16_t>(len,sizeof(junk)));
    }
  }
  // flush
  uint16_t rem = w5500.getRXReceivedSize(MACRAW_SOCKET);
  while (rem) {
    uint8_t junk[64];
    uint16_t c = min<uint16_t>(rem,sizeof(junk));
    recv(MACRAW_SOCKET, junk, c);
    rem -= c;
  }
  return mac;
}

String getBanner(EthernetClient& client) {
  String b="";
  unsigned long start=millis();
  while(client.connected() && millis()-start<300) {
    while(client.available()) {
      char c=client.read();
      if(c=='\n') return b;
      b+=c;
    }
  }
  return b;
}

String checkDevice(IPAddress target) {
  // Önbellekten kontrol
  String cached = getCachedResult(target);
  if(cached != "") return cached;

  String res = "";
  EthernetClient tc;
  
  // TCP port taraması
  for (int i=0; i<sizeof(tcpPorts)/sizeof(int); i++) {
    if(connectWithTimeout(tc, target, tcpPorts[i], 1000)) {
      String ban = getBanner(tc);
      tc.stop();
      res += String(tcpPorts[i])+"(TCP)";
      if(ban.length()) res += ":"+ban;
      res += "\n";
    }
    delay(10); // Ağ yükünü dengele
  }
  
  // UDP port taraması
  EthernetUDP udp;
  if(udp.begin(1024)) {
    for (int i=0; i<sizeof(udpPorts)/sizeof(int); i++) {
      udp.beginPacket(target, udpPorts[i]);
      udp.write("ping", 4);
      udp.endPacket();
      
      // UDP yanıt bekleme süresini artır
      unsigned long start = millis();
      while(millis() - start < 200) {
        if(udp.parsePacket()) {
          res += String(udpPorts[i])+"(UDP)\n";
          break;
        }
        delay(1);
      }
      delay(10); // Ağ yükünü dengele
    }
    udp.stop();
  }
  
  return res;
}

void scanTask(void *pv) {
  ScanTaskParams *p = (ScanTaskParams*)pv;
  int idx = p->startIndex;
  
  while(idx <= 254) {
    IPAddress tgt(localIP[0], localIP[1], localIP[2], idx);
    
    // Önce TCP 80 portu ile hızlı kontrol
    EthernetClient c;
    if(connectWithTimeout(c, tgt, 80, 500)) {
      c.stop();
      
      // MAC adresi tespiti
      String mac = getMacForIP(tgt, 1000);
      if(mac == "") mac = "bilinmiyor";
      
      // Detaylı port taraması
      String det = checkDevice(tgt);
      
      // Sonuçları önbelleğe al
      cacheResult(tgt, mac, det);
      
      String msg = "<strong>" + tgt.toString() + 
                   " (" + mac + ")</strong><br>" + det;
                   
      if(xSemaphoreTake(scanMutex, portMAX_DELAY)) {
        scanResult += "<li>" + msg + "</li>";
        scannedIPs++;
        xSemaphoreGive(scanMutex);
      }
      
      webSocket.broadcastTXT(msg);
      Serial.println(msg);
    }
    
    idx += p->step;
    vTaskDelay(10); // Task'lar arası dengeleme
  }
  
  if(xSemaphoreTake(scanMutex,portMAX_DELAY)) {
    tasksCompleted++;
    if(tasksCompleted>=NUM_SCAN_TASKS) {
      scanning = false;
      webSocket.broadcastTXT("Tarama tamamlandı");
    }
    xSemaphoreGive(scanMutex);
  }
  free(p);
  vTaskDelete(NULL);
}

void ledBlinkTask(void *pv) {
  while(scanning) {
    digitalWrite(LED_PIN,HIGH);
    vTaskDelay(300/portTICK_PERIOD_MS);
    digitalWrite(LED_PIN,LOW);
    vTaskDelay(300/portTICK_PERIOD_MS);
  }
  digitalWrite(LED_PIN,LOW);
  vTaskDelete(NULL);
}

void handleRoot() {
  if(!SPIFFS.begin(true)) {
    server.send(500,"text/plain","SPIFFS hata");
    return;
  }
  File f=SPIFFS.open("/index.html","r");
  server.streamFile(f,"text/html");
  f.close();
}

void handleScanStart() {
  if(!scanning) {
    scanning=true;
    scanResult="<ul>"; tasksCompleted=0; scannedIPs=0;
    xTaskCreate(ledBlinkTask,"LedBlink",1024,NULL,1,NULL);
    for(int i=0;i<NUM_SCAN_TASKS;i++){
      ScanTaskParams *pr=(ScanTaskParams*)malloc(sizeof(ScanTaskParams));
      pr->startIndex=i; pr->step=NUM_SCAN_TASKS;
      xTaskCreate(scanTask,"ScanTask",8192,pr,1,NULL);
    }
    server.send(200,"text/html","<h1>Tarama Başladı</h1>");
  } else {
    server.send(200,"text/html","<h1>Tarama Aktif</h1>");
  }
}

void handleNetworkInfo() {
  DynamicJsonDocument d(256);
  d["ip"]     = localIP.toString();
  d["subnet"] = mySubnetMask.toString();
  d["gateway"]= gatewayIP.toString();
  d["dns"]    = dnsIP.toString();
  String js; serializeJson(d,js);
  server.send(200,"application/json",js);
}

void webSocketEvent(uint8_t u, WStype_t t, uint8_t* p, size_t l) {
  if(t==WStype_TEXT) webSocket.broadcastTXT(scanResult);
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN,OUTPUT); digitalWrite(LED_PIN,LOW);
  WiFi.softAP(ssid,password);
  server.on("/", handleRoot);
  server.on("/scan", handleScanStart);
  server.on("/network-info", handleNetworkInfo);
  server.begin();
  webSocket.begin(); webSocket.onEvent(webSocketEvent);

  SPI.begin(18,19,23,CS_PIN);
  Ethernet.init(CS_PIN);
  if(Ethernet.begin(localMac)==0){
    IPAddress fb(192,168,1,178);
    Ethernet.begin(localMac,fb);
  }
  delay(1000);
  localIP      = Ethernet.localIP();
  mySubnetMask = Ethernet.subnetMask();
  gatewayIP    = Ethernet.gatewayIP();
  dnsIP        = Ethernet.dnsServerIP();
  Serial.printf("IP: %s  Subnet: %s  GW: %s  DNS: %s\n\n",
                localIP.toString().c_str(),
                mySubnetMask.toString().c_str(),
                gatewayIP.toString().c_str(),
                dnsIP.toString().c_str());

  scanMutex = xSemaphoreCreateMutex();

  // MACRAW socket aç
  if(!socket(MACRAW_SOCKET, SnMR::MACRAW, 0, 0)) {
    Serial.println("ERROR: MACRAW socket");
    while(1);
  }
}

void loop() {
  server.handleClient();
  webSocket.loop();
}
