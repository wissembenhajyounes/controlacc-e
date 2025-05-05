#include <WiFiManager.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ArduinoJson.h>

// Configuration serveur
const char* serverUrl = "http://192.168.100.19:5000/verifier_acces";

// Configuration RFID
#define SS_PIN 5
#define RST_PIN 22
MFRC522 mfrc522(SS_PIN, RST_PIN);

// Configuration Relais et LED
#define RELAY_PIN 26    // Relais intégré numéro 1 (changez selon besoin)
#define LED_PIN 2      // LED intégrée ou externe pour feedback visuel
bool doorOpen = false;
unsigned long doorOpenTime = 0;

// Configuration clavier
const byte ROWS = 4;
const byte COLS = 4;
char keys[ROWS][COLS] = {
    {'1','2','3','A'},
    {'4','5','6','B'},
    {'7','8','9','C'},
    {'*','0','#','D'}
};

byte colPins[COLS] = {33, 32, 25, 13
}; // Colonnes (OUTPUT)
byte rowPins[ROWS] = {15, 2, 14, 27};  // Lignes (INPUT_PULLUP)
String pinBuffer = "";

void setupWiFi() {
    WiFiManager wifiManager;
    wifiManager.setConnectTimeout(30);
    wifiManager.setTimeout(180);
    
    if (!wifiManager.autoConnect("DoorAccessSystem")) {
        Serial.println("Échec connexion WiFi");
        delay(3000);
        ESP.restart();
    }
    Serial.print("Connecté! IP: ");
    Serial.println(WiFi.localIP());
}

void readRFID() {
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) 
        return;

    String tagID = "";
    for (byte i = 0; i < mfrc522.uid.size; i++) {
        tagID += String(mfrc522.uid.uidByte[i], HEX);
    }
    tagID.toUpperCase();

    Serial.print("UID RFID: ");
    Serial.println(tagID);
    
    if (sendToServer("card_id", tagID)) {
        openDoor();
    } else {
        Serial.println("Accès refusé (RFID)");
    }

    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
}

void scanKeypad() {
    // Configurer les colonnes en sortie et les mettre à HIGH initialement
    for (byte c = 0; c < COLS; c++) {
        pinMode(colPins[c], OUTPUT);
        digitalWrite(colPins[c], HIGH);
    }

    // Configurer les lignes en entrée avec pull-up
    for (byte r = 0; r < ROWS; r++) {
        pinMode(rowPins[r], INPUT_PULLUP);
    }

    // Scanner chaque colonne
    for (byte c = 0; c < COLS; c++) {
        digitalWrite(colPins[c], LOW); // Activer la colonne
        
        // Vérifier chaque ligne
        for (byte r = 0; r < ROWS; r++) {
            if (digitalRead(rowPins[r]) == LOW) {
                char key = keys[r][c];
                handleKeyPress(key);
                
                // Anti-rebond
                while (digitalRead(rowPins[r]) == LOW) delay(10);
            }
        }
        
        digitalWrite(colPins[c], HIGH); // Désactiver la colonne
        delayMicroseconds(100);
    }
}

void handleKeyPress(char key) {
    Serial.print("Touche détectée: ");
    Serial.println(key);
    
    if (key == '#') { // Validation
        if (pinBuffer.length() == 6) {
            Serial.print("Code PIN saisi: ");
            Serial.println(pinBuffer);
            if (sendToServer("code_pin", pinBuffer)) {
                openDoor();
            } else {
                Serial.println("Accès refusé (PIN)");
            }
            pinBuffer = "";
        } else {
            Serial.println("PIN invalide (6 chiffres requis)");
        }
    } 
    else if (key == '*') { // Effacement
        pinBuffer = "";
        Serial.println("PIN effacé");
    }
    else if (pinBuffer.length() < 6) {
        pinBuffer += key;
        Serial.print("PIN actuel: ");
        Serial.println(pinBuffer);
    }
}

bool sendToServer(String param, String value) {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("Erreur: Pas de connexion WiFi");
        return false;
    }

    HTTPClient http;
    String url = String(serverUrl) + "?" + param + "=" + value;
    
    http.begin(url);
    http.setTimeout(5000);
    int httpCode = http.GET();
    
    if (httpCode == HTTP_CODE_OK) {
        String payload = http.getString();
        DynamicJsonDocument doc(256);
        deserializeJson(doc, payload);
        
        bool access = doc["status"] == "AUTHORIZED";
        http.end();
        return access;
    } else {
        Serial.print("Erreur HTTP: ");
        Serial.println(httpCode);
    }
    
    http.end();
    return false;
}

void openDoor() {
    Serial.println("Ouverture porte - Activation relais");
    digitalWrite(RELAY_PIN, LOW);  // Active le relais (LOW pour les cartes à relais actif bas)
    digitalWrite(LED_PIN, HIGH);   // Allume la LED
    doorOpen = true;
    doorOpenTime = millis();
}

void closeDoor() {
    if (doorOpen) {
        Serial.println("Fermeture porte - Désactivation relais");
        digitalWrite(RELAY_PIN, HIGH); // Désactive le relais
        digitalWrite(LED_PIN, LOW);    // Éteint la LED
        doorOpen = false;
    }
}

void setup() {
    Serial.begin(115200);
    while (!Serial);
    
    SPI.begin();
    mfrc522.PCD_Init();
    
    // Configuration relais et LED
    pinMode(RELAY_PIN, OUTPUT);
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(RELAY_PIN, HIGH); // Relais désactivé au démarrage
    digitalWrite(LED_PIN, LOW);    // LED éteinte au démarrage
    
    WiFi.mode(WIFI_STA);
    setupWiFi();
    
    Serial.println("Système prêt (RFID + Clavier + Relais)");
    Serial.println("Broche relais: " + String(RELAY_PIN));
    Serial.println("Broche LED: " + String(LED_PIN));
}

void loop() {
    if (WiFi.status() != WL_CONNECTED) {
        WiFi.reconnect();
        delay(5000);
        return;
    }

    readRFID();
    scanKeypad();
    
    // Fermeture automatique après 5 secondes
    if (doorOpen && (millis() - doorOpenTime >= 5000)) {
        closeDoor();
    }
}