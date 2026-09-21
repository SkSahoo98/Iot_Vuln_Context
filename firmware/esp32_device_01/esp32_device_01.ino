/*
 * ESP32-01 — DHT22 → MQTT telemetry for IoT Security Framework
 *
 * Topic: iot/esp32/01/sensor
 * Payload:
 * {
 *   "device_id": "ESP32-01",
 *   "ip_address": "<WiFi.localIP()>",
 *   "temperature": 32.40,
 *   "humidity": 75.30
 * }
 *
 * Setup:
 * 1. Copy secrets.h.example → secrets.h
 * 2. Fill Wi-Fi SSID/password and MQTT broker host (lab only)
 * 3. Flash with Arduino IDE / PlatformIO
 *
 * Do NOT commit secrets.h (contains Wi-Fi credentials).
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include <DHT.h>
#include "secrets.h"

#define DEVICE_ID "ESP32-01"
#define MQTT_TOPIC "iot/esp32/01/sensor"
#define DHT_PIN 4
#define DHT_TYPE DHT22
#define PUBLISH_INTERVAL_MS 5000

DHT dht(DHT_PIN, DHT_TYPE);
WiFiClient wifiClient;
PubSubClient mqtt(wifiClient);

unsigned long lastPublishMs = 0;

void connectWiFi() {
  Serial.printf("Connecting to Wi-Fi SSID: %s\n", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println();
  Serial.println("WiFi connected");
  Serial.print("ESP32 IP: ");
  Serial.println(WiFi.localIP());
}

void connectMqtt() {
  while (!mqtt.connected()) {
    Serial.print("Connecting to MQTT broker ");
    Serial.print(MQTT_BROKER_HOST);
    Serial.print(" ... ");

    bool ok;
    if (strlen(MQTT_USERNAME) > 0) {
      ok = mqtt.connect(DEVICE_ID, MQTT_USERNAME, MQTT_PASSWORD);
    } else {
      ok = mqtt.connect(DEVICE_ID);
    }

    if (ok) {
      Serial.println("connected");
    } else {
      Serial.print("failed, rc=");
      Serial.println(mqtt.state());
      delay(2000);
    }
  }
}

void publishTelemetry() {
  float temperature = dht.readTemperature();
  float humidity = dht.readHumidity();

  if (isnan(temperature) || isnan(humidity)) {
    Serial.println("DHT22 read failed — skipping publish");
    return;
  }

  // Transient DHT22 failures often return exactly 0.0/0.0 — do not publish.
  if (temperature == 0.0f && humidity == 0.0f) {
    Serial.println("DHT22 invalid 0/0 reading — skipping publish");
    return;
  }

  String ip = WiFi.localIP().toString();

  // Build JSON without inventing values — IP comes from WiFi.localIP().
  String payload = "{";
  payload += "\"device_id\":\"";
  payload += DEVICE_ID;
  payload += "\",\"ip_address\":\"";
  payload += ip;
  payload += "\",\"temperature\":";
  payload += String(temperature, 2);
  payload += ",\"humidity\":";
  payload += String(humidity, 2);
  payload += "}";

  if (mqtt.publish(MQTT_TOPIC, payload.c_str())) {
    Serial.print("Published: ");
    Serial.println(payload);
  } else {
    Serial.println("MQTT publish failed");
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println();
  Serial.println("ESP32-01 IoT Security Framework telemetry");

  dht.begin();
  connectWiFi();

  mqtt.setServer(MQTT_BROKER_HOST, MQTT_BROKER_PORT);
  connectMqtt();
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }

  if (!mqtt.connected()) {
    connectMqtt();
  }
  mqtt.loop();

  unsigned long now = millis();
  if (now - lastPublishMs >= PUBLISH_INTERVAL_MS) {
    lastPublishMs = now;
    publishTelemetry();
  }
}
