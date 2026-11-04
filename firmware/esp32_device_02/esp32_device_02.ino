
/*
 * ESP32-02 — DHT22 to MQTT Telemetry
 * IoT Security Framework
 *
 * Device ID: ESP32-02
 * MQTT Broker: 10.32.252.85:1883
 * MQTT Username: esp32_02
 * MQTT Topic: iot/esp32/02/sensor
 *
 * Sensor: DHT22
 * GPIO: 4
 * Publishing interval: 5000 ms
 *
 * Credentials are stored in secrets.h.
 * Never commit secrets.h to Git.
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include <DHT.h>
#include <cstring>
#include "secrets.h"

// ==========================================
// DEVICE CONFIGURATION
// ==========================================

#define DEVICE_ID "ESP32-02"

#define MQTT_TOPIC "iot/esp32/02/sensor"

#define DHT_PIN 4
#define DHT_TYPE DHT22

#define PUBLISH_INTERVAL_MS 5000
#define WIFI_RECONNECT_INTERVAL_MS 5000

// ==========================================
// OBJECT INITIALIZATION
// ==========================================

DHT dht(DHT_PIN, DHT_TYPE);

WiFiClient wifiClient;
PubSubClient mqtt(wifiClient);

// ==========================================
// GLOBAL VARIABLES
// ==========================================

unsigned long lastPublishMs = 0;
unsigned long lastWiFiAttemptMs = 0;

bool mqttCredentialsValid = false;

// ==========================================
// WIFI CONNECTION
// ==========================================

void connectWiFi() {

  if (WiFi.status() == WL_CONNECTED) {
    return;
  }

  Serial.print("Connecting to Wi-Fi SSID: ");
  Serial.println(WIFI_SSID);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  unsigned long startAttempt = millis();

  while (WiFi.status() != WL_CONNECTED &&
         millis() - startAttempt < 20000) {

    delay(500);
    Serial.print(".");
  }

  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {

    Serial.println("Wi-Fi connected!");

    Serial.print("ESP32 IP: ");
    Serial.println(WiFi.localIP());

  } else {

    Serial.println("Wi-Fi connection failed.");
    Serial.println("Will retry later.");

  }
}

// ==========================================
// MQTT CONNECTION
// ==========================================

void connectMqtt() {

  // Never allow anonymous MQTT access.
  if (!mqttCredentialsValid) {

    Serial.println("FATAL: MQTT credentials missing in secrets.h.");
    Serial.println("Anonymous MQTT access is disabled.");

    return;
  }

  if (WiFi.status() != WL_CONNECTED) {
    return;
  }

  while (!mqtt.connected()) {

    Serial.print("Connecting to MQTT broker: ");
    Serial.print(MQTT_BROKER_HOST);

    Serial.print(" as user: ");
    Serial.print(MQTT_USERNAME);

    Serial.println(" ...");

    // Authenticated MQTT connection.
    bool connected = mqtt.connect(
      DEVICE_ID,
      MQTT_USERNAME,
      MQTT_PASSWORD
    );

    if (connected) {

      Serial.println("MQTT authenticated connection successful!");

    } else {

      Serial.print("MQTT connection failed. State: ");
      Serial.println(mqtt.state());

      Serial.println("Retrying in 2 seconds...");

      delay(2000);

    }
  }
}

// ==========================================
// DHT22 TELEMETRY PUBLISHING
// ==========================================

void publishTelemetry() {

  if (!mqtt.connected()) {
    Serial.println("MQTT disconnected. Skipping publish.");
    return;
  }

  float temperature = dht.readTemperature();
  float humidity = dht.readHumidity();

  // Validate sensor readings.
  if (isnan(temperature) || isnan(humidity)) {

    Serial.println("DHT22 reading failed. Skipping publish.");

    return;
  }

  // Reject invalid 0/0 readings.
  if (temperature == 0.0f && humidity == 0.0f) {

    Serial.println("Invalid DHT22 0/0 reading.");

    return;
  }

  // Obtain actual device IP address.
  String ipAddress = WiFi.localIP().toString();

  // Build JSON payload.
  String payload = "{";

  payload += "\"device_id\":\"";
  payload += DEVICE_ID;

  payload += "\",\"ip_address\":\"";
  payload += ipAddress;

  payload += "\",\"temperature\":";
  payload += String(temperature, 2);

  payload += ",\"humidity\":";
  payload += String(humidity, 2);

  payload += "}";

  // Publish telemetry.
  bool published = mqtt.publish(
    MQTT_TOPIC,
    payload.c_str()
  );

  if (published) {

    Serial.println("Telemetry published successfully:");

    Serial.println(payload);

  } else {

    Serial.println("MQTT telemetry publishing failed.");

  }
}

// ==========================================
// SETUP
// ==========================================

void setup() {

  Serial.begin(115200);

  delay(1000);

  Serial.println();

  Serial.println("================================");
  Serial.println("ESP32-02 IoT Security Framework");
  Serial.println("Authenticated MQTT Telemetry");
  Serial.println("================================");

  // Validate MQTT credentials once.
  mqttCredentialsValid =
    strlen(MQTT_USERNAME) > 0 &&
    strlen(MQTT_PASSWORD) > 0;

  if (!mqttCredentialsValid) {

    Serial.println("ERROR: MQTT credentials missing.");
    Serial.println("Update secrets.h before connecting.");

  }

  // Initialize DHT22.
  dht.begin();

  Serial.println("DHT22 initialized.");

  // Configure MQTT broker.
  mqtt.setServer(
    MQTT_BROKER_HOST,
    MQTT_BROKER_PORT
  );

  mqtt.setKeepAlive(30);
  mqtt.setSocketTimeout(5);

  // Connect Wi-Fi.
  connectWiFi();

  // Connect MQTT if credentials and Wi-Fi are available.
  if (WiFi.status() == WL_CONNECTED &&
      mqttCredentialsValid) {

    connectMqtt();

  }

  lastWiFiAttemptMs = millis();
}

// ==========================================
// MAIN LOOP
// ==========================================

void loop() {

  unsigned long currentMillis = millis();

  // ----------------------------------------
  // Wi-Fi reconnection management
  // ----------------------------------------

  if (WiFi.status() != WL_CONNECTED) {

    if (currentMillis - lastWiFiAttemptMs >=
        WIFI_RECONNECT_INTERVAL_MS) {

      lastWiFiAttemptMs = currentMillis;

      connectWiFi();

    }

    return;
  }

  // ----------------------------------------
  // MQTT reconnection management
  // ----------------------------------------

  if (!mqtt.connected()) {

    if (mqttCredentialsValid) {
      connectMqtt();
    }

  } else {

    mqtt.loop();

  }

  // ----------------------------------------
  // Periodic sensor publishing
  // ----------------------------------------

  if (mqtt.connected() &&
      currentMillis - lastPublishMs >=
      PUBLISH_INTERVAL_MS) {

    lastPublishMs = currentMillis;

    publishTelemetry();

  }
}
