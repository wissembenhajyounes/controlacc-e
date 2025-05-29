#include <WiFiManager.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ArduinoJson.h>
#include <EEPROM.h>

// Configuration du watchdog - utilisation de la méthode standard Arduino
const unsigned long WDT_TIMEOUT = 8000; // 8 secondes en millisecondes

// Configuration serveur
const char* serverUrl = "http://192.168.100.19:5000/verifier_acces";

// Variables pour la configuration IP manuelle
char ip_address[16] = "";      // Pour stocker l'adresse IP du serveur
char port_str[6] = "5000";     // Port par défaut
bool configurationMode = false;

// Configuration RFID
#define SS_PIN 5
#define RST_PIN 22
MFRC522 mfrc522(SS_PIN, RST_PIN);

// Configuration Relais - DÉFINITION CONSTANTE ET DÉFINITIVE
#define RELAY_PIN 26    // Relais principal pour la serrure - TOUJOURS UTILISER CETTE BROCHE
const int RELAY_OPEN_STATE = LOW;   // État du relais pour ouvrir la porte
const int RELAY_CLOSE_STATE = HIGH; // État du relais pour fermer la porte
bool doorOpen = false;
unsigned long doorOpenTime = 0;
const unsigned long DOOR_OPEN_DURATION = 2000; // Durée d'ouverture de la porte en ms (2 secondes)

// Adresse EEPROM pour stocker la configuration du relais
#define EEPROM_RELAY_CHECK 0
#define EEPROM_RELAY_VALUE 42  // Valeur magique pour vérifier la configuration

// Paramètres RFID
const int MAX_RFID_READ_ATTEMPTS = 3;
const int RFID_READ_INTERVAL = 50;
const int RFID_GAIN = MFRC522::RxGain_max;

// Configuration clavier
const byte ROWS = 4;
const byte COLS = 4;
char keys[ROWS][COLS] = {
    {'1','2','3','A'},
    {'4','5','6','B'},
    {'7','8','9','C'},
    {'*','0','#','D'}
};
byte colPins[COLS] = {33, 32, 25, 13};
byte rowPins[ROWS] = {15, 2, 14, 27};  
String pinBuffer = "";

// Variables pour l'anti-répétition du clavier
bool keyState[ROWS][COLS] = {0}; // État des touches (0 = relâchée, 1 = pressée)
const unsigned long KEY_REPEAT_DELAY = 500; // Délai avant de considérer une nouvelle pression (ms)
unsigned long lastKeyPressTime[ROWS][COLS] = {0}; // Dernière pression pour chaque touche

// Variables de timing
unsigned long lastKeypadScan = 0;
unsigned long lastRfidScan = 0;
unsigned long lastRfidReset = 0;
unsigned long lastWatchdogReset = 0;
const int KEYPAD_SCAN_INTERVAL = 20;
const int RFID_SCAN_INTERVAL = 100;
const int RFID_RESET_INTERVAL = 30000; // Réinitialiser le RFID toutes les 30 secondes
const int WATCHDOG_RESET_INTERVAL = 1000; // Réinitialiser le watchdog toutes les secondes
unsigned long keypadTimeout = 0;
const unsigned long KEYPAD_TIMEOUT_DURATION = 10000;

// Protection anti-bruteforce
bool isSystemBlocked = false;
unsigned long systemBlockedUntil = 0;
const unsigned long LOCAL_BLOCK_DURATION = 30000;
int consecutiveFailures = 0;
const int MAX_LOCAL_FAILURES = 3;

// Gestion WiFi
unsigned long lastWifiReconnectAttempt = 0;
const unsigned long WIFI_RECONNECT_INTERVAL = 5000;
int wifiReconnectCount = 0;
const int MAX_WIFI_RECONNECT_ATTEMPTS = 5;

// Statistiques
unsigned long lastHeartbeat = 0;
const unsigned long HEARTBEAT_INTERVAL = 60000;
unsigned long systemUptime = 0;
unsigned long successfulAccesses = 0;
unsigned long failedAccesses = 0;

// Compteur de réinitialisation RFID
unsigned long rfidResetCount = 0;

// Mutex pour protéger les ressources partagées
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;

// Fonction de réinitialisation du lecteur RFID
void resetRFIDReader() {
    portENTER_CRITICAL(&mux);
    rfidResetCount++;
    portEXIT_CRITICAL(&mux);
    
    Serial.println("Réinitialisation du lecteur RFID...");
    
    // Arrêter la communication avec la carte actuelle si elle existe
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    
    // Réinitialiser le lecteur RFID
    mfrc522.PCD_Reset();
    delay(50);
    
    // Réinitialiser SPI
    SPI.end();
    delay(100);
    SPI.begin();
    
    // Réinitialiser le lecteur RFID
    mfrc522.PCD_Init(SS_PIN, RST_PIN);
    delay(50);
    
    // Configurer le gain d'antenne
    mfrc522.PCD_SetAntennaGain(RFID_GAIN);
    
    Serial.println("Lecteur RFID réinitialisé avec succès");
    
    // Afficher la version du firmware pour vérification
    byte v = mfrc522.PCD_ReadRegister(mfrc522.VersionReg);
    Serial.print("Version MFRC522: 0x");
    Serial.println(v, HEX);
    
    if (v == 0x91 || v == 0x92) {
        Serial.println("Version du lecteur RFID confirmée");
    } else {
        Serial.println("ATTENTION: Version du lecteur RFID non reconnue");
    }
}

void setup() {
    // Initialiser la communication série
    Serial.begin(115200);
    Serial.println("\n\n--- Système de contrôle d'accès ---");
    
    // Configurer le watchdog - utilisation de la méthode standard Arduino
    Serial.println("Configuration du watchdog...");
    // Nous utilisons le watchdog matériel standard de l'ESP32
    // qui redémarrera automatiquement si le programme se bloque
    
    // Initialiser l'EEPROM
    EEPROM.begin(512);
    
    // Configurer les broches
    pinMode(RELAY_PIN, OUTPUT);
    digitalWrite(RELAY_PIN, RELAY_CLOSE_STATE); // S'assurer que la porte est fermée au démarrage
    
    Serial.println("\n=== SYSTÈME DE CONTRÔLE D'ACCÈS RFID/PIN ===");
    Serial.println("Version: 1.6 - Utilisation exclusive du relais principal (broche 26)");
    Serial.println("Initialisation...");
    
    SPI.begin();
    mfrc522.PCD_Init();
    mfrc522.PCD_SetAntennaGain(RFID_GAIN);
    
    WiFi.mode(WIFI_STA);
    setupWiFi();
    
    Serial.println("Système prêt (RFID + Clavier + Relais)");
    Serial.println("Broche relais principal: " + String(RELAY_PIN) + " (utilisation exclusive)");
    Serial.println("Adresse MAC: " + getMacAddress()); // Ajoutez cette ligne
    Serial.println("Tapez 'help' pour afficher les commandes disponibles");
    
    // Tester la connexion au serveur
    if (testServerConnection()) {
        Serial.println("Connexion au serveur réussie");
    } else {
        Serial.println("Échec de connexion au serveur, vérifiez l'adresse IP et le port");
    }
    
    // Initialiser l'état du système
    doorOpen = false;
    isSystemBlocked = false;
    
    // Initialiser les timers
    lastWatchdogReset = millis();
    lastRfidReset = millis();
    
    // Initialiser l'état des touches du clavier
    for (byte r = 0; r < ROWS; r++) {
        for (byte c = 0; c < COLS; c++) {
            keyState[r][c] = false;
            lastKeyPressTime[r][c] = 0;
        }
    }
    
    // Réinitialiser le lecteur RFID au démarrage
    resetRFIDReader();
    
    Serial.println("Système prêt!");
    Serial.println("Attente de carte RFID ou saisie de code PIN...");
}

void loop() {
    // Vérifier si la porte doit être fermée
    if (doorOpen && (millis() - doorOpenTime > DOOR_OPEN_DURATION)) {
        closeDoor();
    }
    
    // Réinitialiser périodiquement le lecteur RFID pour éviter les blocages
    if (millis() - lastRfidReset > RFID_RESET_INTERVAL) {
        lastRfidReset = millis();
        resetRFIDReader();
    }
    
    // Vérifier les commandes série
    checkSerialCommand();
    
    // Lire le RFID - fonctionne indépendamment du clavier
    readRFID();
    
    // Scanner le clavier - fonctionne indépendamment du RFID
    scanKeypad();
    
    // Afficher les statistiques périodiquement
    printHeartbeat();
    
    // Réinitialiser le watchdog périodiquement
    if (millis() - lastWatchdogReset > WATCHDOG_RESET_INTERVAL) {
        lastWatchdogReset = millis();
        // Le watchdog est géré par le système Arduino ESP32
        yield(); // Permet au système de traiter les tâches en attente
    }
}

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

unsigned long safeMillis() {
    return millis();
}

bool checkWifiConnection() {
    if (WiFi.status() != WL_CONNECTED) {
        unsigned long currentMillis = safeMillis();
        if (currentMillis - lastWifiReconnectAttempt >= WIFI_RECONNECT_INTERVAL) {
            lastWifiReconnectAttempt = currentMillis;
            wifiReconnectCount++;
            Serial.println("Tentative de reconnexion WiFi #" + String(wifiReconnectCount));
            
            bool reconnectSuccess = WiFi.reconnect();
            
            if (wifiReconnectCount >= MAX_WIFI_RECONNECT_ATTEMPTS && !reconnectSuccess) {
                Serial.println("Trop de tentatives de reconnexion WiFi échouées, redémarrage...");
                ESP.restart();
            }
            
            return reconnectSuccess;
        }
        return false;
    } else {
        wifiReconnectCount = 0;
        return true;
    }
}

void readRFID() {
    // Vérifier si le système est bloqué
    if (isSystemBlocked) {
        if (safeMillis() < systemBlockedUntil) return;
        isSystemBlocked = false;
    }
    
    // Limiter la fréquence de scan RFID
    unsigned long currentMillis = safeMillis();
    if (currentMillis - lastRfidScan < RFID_SCAN_INTERVAL) return;
    lastRfidScan = currentMillis;

    // Variables pour la lecture RFID
    bool tagFound = false;
    String tagID = "";
    
    // Essayer de lire une carte plusieurs fois pour améliorer la fiabilité
    for (int attempt = 0; attempt < MAX_RFID_READ_ATTEMPTS; attempt++) {
        // Optimiser les paramètres de lecture
        mfrc522.PCD_SetAntennaGain(RFID_GAIN);
        
        // Vérifier si une nouvelle carte est présente
        if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
            tagFound = true;
            tagID = "";
            for (byte i = 0; i < mfrc522.uid.size; i++) {
                tagID += String(mfrc522.uid.uidByte[i], HEX);
            }
            tagID.toUpperCase();
            break;
        }
        delay(RFID_READ_INTERVAL);
    }

    // Si une carte a été trouvée
    if (tagFound) {
        Serial.print("UID RFID: ");
        Serial.println(tagID);
        
        // Vérifier la connexion WiFi
        if (!checkWifiConnection()) {
            Serial.println("Pas de connexion WiFi, impossible de vérifier l'accès");
            
            // Libérer les ressources RFID
            mfrc522.PICC_HaltA();
            mfrc522.PCD_StopCrypto1();
            return;
        }
        
        // Envoyer l'ID de la carte au serveur
        if (sendToServer("card_id", tagID)) {
            consecutiveFailures = 0;
            successfulAccesses++;
            openDoor();
        } else {
            Serial.println("Accès refusé (RFID)");
            consecutiveFailures++;
            failedAccesses++;
            
            if (consecutiveFailures >= MAX_LOCAL_FAILURES) {
                blockSystemTemporarily();
            }
        }
        
        // Libérer les ressources RFID
        mfrc522.PICC_HaltA();
        mfrc522.PCD_StopCrypto1();
    }
}

void scanKeypad() {
    // Ne pas scanner le clavier si le système est bloqué
    if (isSystemBlocked) {
        if (safeMillis() < systemBlockedUntil) return;
        isSystemBlocked = false;
    }
    
    // Limiter la fréquence de scan du clavier
    unsigned long currentMillis = safeMillis();
    if (currentMillis - lastKeypadScan < KEYPAD_SCAN_INTERVAL) return;
    lastKeypadScan = currentMillis;
    
    // Vérifier si le délai de saisie du code PIN est expiré
    if (pinBuffer.length() > 0 && currentMillis > keypadTimeout) {
        Serial.println("Délai de saisie PIN expiré, réinitialisation");
        pinBuffer = "";
    }
    
    // Configuration des broches pour le scan
    for (byte c = 0; c < COLS; c++) {
        pinMode(colPins[c], OUTPUT);
        digitalWrite(colPins[c], HIGH);
    }

    for (byte r = 0; r < ROWS; r++) {
        pinMode(rowPins[r], INPUT_PULLUP);
    }

    // Scan du clavier avec anti-répétition
    for (byte c = 0; c < COLS; c++) {
        digitalWrite(colPins[c], LOW);
        
        for (byte r = 0; r < ROWS; r++) {
            bool currentState = (digitalRead(rowPins[r]) == LOW);
            unsigned long now = millis();
            
            // Détection d'une nouvelle pression (transition de relâchée à pressé)
            if (currentState && !keyState[r][c] && (now - lastKeyPressTime[r][c] > KEY_REPEAT_DELAY)) {
                // Enregistrer le moment de la pression
                lastKeyPressTime[r][c] = now;
                
                // Traiter la touche
                char key = keys[r][c];
                handleKeyPress(key);
                keypadTimeout = now + KEYPAD_TIMEOUT_DURATION;
                
                // Attendre que la touche soit relâchée pour éviter les répétitions
                // mais avec un timeout pour ne pas bloquer le système
                unsigned long debounceStart = now;
                while (digitalRead(rowPins[r]) == LOW && (millis() - debounceStart < 300)) {
                    delay(1);
                    yield(); // Permet au système de traiter les tâches en attente
                }
            }
            
            // Mettre à jour l'état de la touche
            keyState[r][c] = currentState;
        }
        
        digitalWrite(colPins[c], HIGH);
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
            
            // Vérifier la connexion WiFi
            if (!checkWifiConnection()) {
                Serial.println("Pas de connexion WiFi, impossible de vérifier l'accès");
                pinBuffer = "";
                return;
            }
            
            // Envoyer le code PIN au serveur
            if (sendToServer("code_pin", pinBuffer)) {
                consecutiveFailures = 0;
                successfulAccesses++;
                openDoor();
            } else {
                Serial.println("Accès refusé (PIN)");
                consecutiveFailures++;
                failedAccesses++;
                
                if (consecutiveFailures >= MAX_LOCAL_FAILURES) {
                    blockSystemTemporarily();
                }
            }
            pinBuffer = "";
        } else {
            Serial.println("PIN invalide (6 chiffres requis)");
            pinBuffer = "";
        }
    } 
    else if (key == '*') { // Effacement
        pinBuffer = "";
        Serial.println("PIN effacé");
    }
    else if (pinBuffer.length() < 6) { // Ajout d'un chiffre
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

    // Récupérer l'adresse MAC
    String macAddress = getMacAddress();

    // Construit l'URL dynamiquement avec l'adresse MAC incluse
    String url;
    if (strlen(ip_address) > 0) {
        url = "http://" + String(ip_address) + ":" + String(port_str) + "/verifier_acces?" + param + "=" + value + "&mac_address=" + macAddress;
    } else {
        url = String(serverUrl) + "?" + param + "=" + value + "&mac_address=" + macAddress;
    }
    
    Serial.print("Connexion à: ");
    Serial.println(url);

    HTTPClient http;
    http.begin(url);
    http.setTimeout(5000);
    
    int retries = 3;
    int httpCode = -1;
    
    while (retries > 0 && httpCode < 0) {
        httpCode = http.GET();
        
        if (httpCode < 0) {
            Serial.printf("Erreur HTTP: %s, tentatives restantes: %d\n", http.errorToString(httpCode).c_str(), retries - 1);
            
            // Tentative de diagnostic plus précise
            if (httpCode == HTTPC_ERROR_CONNECTION_REFUSED) {
                Serial.println("Le serveur a refusé la connexion. Vérifiez que le serveur Flask est en cours d'exécution.");
            } else if (httpCode == HTTPC_ERROR_CONNECTION_LOST) {
                Serial.println("Connexion perdue pendant la requête.");
            } else if (httpCode == HTTPC_ERROR_SEND_HEADER_FAILED) {
                Serial.println("Échec d'envoi des en-têtes HTTP.");
            } else if (httpCode == HTTPC_ERROR_SEND_PAYLOAD_FAILED) {
                Serial.println("Échec d'envoi des données.");
            }
            
            delay(500);
            retries--;
        }
    }
    
    if (httpCode == HTTP_CODE_OK) {
        // Traitement de la réponse OK
        String payload = http.getString();
        DynamicJsonDocument doc(256);
        DeserializationError error = deserializeJson(doc, payload);
        
        if (error) {
            Serial.print("Erreur de parsing JSON: ");
            Serial.println(error.c_str());
            http.end();
            return false;
        }
        
        bool access = doc["status"] == "AUTHORIZED";
        if (access) {
            Serial.println("Accès autorisé par le serveur");
        } else {
            Serial.println("Accès refusé par le serveur");
        }
        http.end();
        return access;
    } else if (httpCode == 429) {
        // Traitement de la limitation de débit (429 Too Many Requests)
        String payload = http.getString();
        DynamicJsonDocument doc(256);
        DeserializationError error = deserializeJson(doc, payload);
        
        if (error) {
            Serial.print("Erreur de parsing JSON (429): ");
            Serial.println(error.c_str());
            blockSystemTemporarily();
            http.end();
            return false;
        }
        
        String message = doc["message"];
        int seconds = 0;
        
        int pos = message.indexOf("dans ");
        if (pos > 0) {
            String timeStr = message.substring(pos + 5);
            seconds = timeStr.toInt();
        }
        
        if (seconds <= 0) seconds = 300;
        
        Serial.print("Blocage détecté! Durée: ");
        Serial.print(seconds);
        Serial.println(" secondes");
        
        blockSystemWithDuration(seconds * 1000);
        
        http.end();
        return false;
    } else {
        Serial.print("Erreur HTTP: ");
        Serial.println(httpCode);
    }
    
    http.end();
    return false;
}

// Fonction pour tester la connexion au serveur
bool testServerConnection() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("Pas de connexion WiFi");
        return false;
    }
    
    String testUrl;
    if (strlen(ip_address) > 0) {
        testUrl = "http://" + String(ip_address) + ":" + String(port_str);
    } else {
        // Extraire l'URL de base du serverUrl
        int endPos = String(serverUrl).indexOf("/", 7); // Après "http://"
        if (endPos > 0) {
            testUrl = String(serverUrl).substring(0, endPos);
        } else {
            testUrl = String(serverUrl);
        }
    }
    
    Serial.print("Test de connexion à: ");
    Serial.println(testUrl);
    
    HTTPClient http;
    http.begin(testUrl);
    http.setTimeout(3000);
    
    int httpCode = http.GET();
    http.end();
    
    if (httpCode > 0) {
        Serial.print("Réponse du serveur: ");
        Serial.println(httpCode);
        return true;
    } else {
        Serial.print("Erreur de connexion: ");
        Serial.println(http.errorToString(httpCode));
        return false;
    }
}

void blockSystemTemporarily() {
    Serial.println("Trop de tentatives échouées, blocage temporaire du système");
    isSystemBlocked = true;
    systemBlockedUntil = safeMillis() + LOCAL_BLOCK_DURATION;
}

void blockSystemWithDuration(unsigned long durationMs) {
    Serial.println("Blocage du système par le serveur");
    isSystemBlocked = true;
    systemBlockedUntil = safeMillis() + durationMs;
}

void openDoor() {
    Serial.println("Ouverture porte - Activation relais sur broche 26");
    
    // Toujours utiliser le relais principal (broche 26) quelle que soit la configuration
    digitalWrite(RELAY_PIN, RELAY_OPEN_STATE);
    
    doorOpen = true;
    doorOpenTime = safeMillis();
}

void closeDoor() {
    if (doorOpen) {
        Serial.println("Fermeture porte - Désactivation relais");
        digitalWrite(RELAY_PIN, RELAY_CLOSE_STATE);
        doorOpen = false;
    }
}

void printHeartbeat() {
    unsigned long currentMillis = safeMillis();
    if (currentMillis - lastHeartbeat >= HEARTBEAT_INTERVAL) {
        lastHeartbeat = currentMillis;
        systemUptime = currentMillis / 1000 / 60;
        
        Serial.println("\n----- STATISTIQUES SYSTÈME -----");
        Serial.print("Temps de fonctionnement: ");
        Serial.print(systemUptime);
        Serial.println(" minutes");
        Serial.print("Accès réussis: ");
        Serial.println(successfulAccesses);
        Serial.print("Accès refusés: ");
        Serial.println(failedAccesses);
        Serial.print("Utilisation du relais: ");
        Serial.println("Principal (broche 26)");
        Serial.print("État WiFi: ");
        Serial.println(WiFi.status() == WL_CONNECTED ? "Connecté" : "Déconnecté");
        Serial.print("Adresse IP: ");
        Serial.println(WiFi.localIP());
        Serial.print("Adresse MAC: "); // Ajoutez cette ligne
        Serial.println(getMacAddress()); // Ajoutez cette ligne
        Serial.println("-----------------------------\n");
    }
}

void checkSerialCommand() {
    if (Serial.available() > 0) {
        String command = Serial.readStringUntil('\n');
        command.trim();
        
        if (command.startsWith("setip ")) {
            // Format attendu: "setip 192.168.100.XX"
            String newIP = command.substring(6);
            newIP.trim();
            if (newIP.length() > 0 && newIP.length() < 16) {
                strcpy(ip_address, newIP.c_str());
                Serial.print("Nouvelle adresse IP du serveur configurée: ");
                Serial.println(ip_address);
            }
        }
        else if (command.startsWith("setport ")) {
            // Format attendu: "setport 5000"
            String newPort = command.substring(8);
            newPort.trim();
            if (newPort.length() > 0 && newPort.length() < 6) {
                strcpy(port_str, newPort.c_str());
                Serial.print("Nouveau port du serveur configuré: ");
                Serial.println(port_str);
            }
        }
        else if (command == "test") {
            // Tester la connexion au serveur
            if (testServerConnection()) {
                Serial.println("Test de connexion au serveur réussi");
            } else {
                Serial.println("Test de connexion au serveur échoué");
            }
        }
        else if (command == "reset") {
            // Réinitialiser le lecteur RFID
            resetRFIDReader();
            Serial.println("Lecteur RFID réinitialisé manuellement");
        }
        else if (command == "stats") {
            // Afficher les statistiques
            printHeartbeat();
        }
        else if (command == "restart") {
            // Redémarrer l'ESP32
            Serial.println("Redémarrage de l'ESP32...");
            delay(1000);
            ESP.restart();
        }
        else if (command == "help") {
            // Afficher l'aide
            Serial.println("\n----- COMMANDES DISPONIBLES -----");
            Serial.println("setip XXX.XXX.XXX.XXX - Configurer l'adresse IP du serveur");
            Serial.println("setport XXXX - Configurer le port du serveur");
            Serial.println("test - Tester la connexion au serveur");
            Serial.println("reset - Réinitialiser le lecteur RFID");
            Serial.println("stats - Afficher les statistiques du système");
            Serial.println("restart - Redémarrer l'ESP32");
            Serial.println("help - Afficher cette aide");
            Serial.println("-----------------------------\n");
        }
        else {
            Serial.println("Commande non reconnue. Tapez 'help' pour voir les commandes disponibles.");
        }
    }
}

// Fonction pour obtenir l'adresse MAC de l'ESP32
String getMacAddress() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  char macStr[18] = { 0 };
  sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(macStr);
}
