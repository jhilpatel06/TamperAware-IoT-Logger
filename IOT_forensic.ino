/* ESP32 Forensic Logger - complete sketch with HTTP attack endpoints
   - Hash-chain: entry_hash = SHA256(prev_hash + (datetime + "," + temp))
   - Trusted final hash stored in Preferences (NVS)
   - HTTP endpoints:
       /show
       /verify
       /attack_edit?line=N&value=XX        (previous simple edit)
       /attack_replace?line=N&csv=a,b,c,d  (replace line with full CSV row)
       /attack_append_csv?csv=a,b,c,d      (append arbitrary CSV row)
       /attack_append?value=XX             (append tampered simple format)
       /attack_overwrite?text=...          (overwrite entire file)
*/

#include <Arduino.h>
#include <SPI.h>
#include <SD.h>
#include <WiFi.h>
#include <WebServer.h>
#include <time.h>
#include <Preferences.h>
#include "mbedtls/sha256.h"

// ---------------- CONFIG ----------------
#define SD_CS 5
const char *DATA_FILE = "/data.csv";

// menus
void printInitMenu();
void printRuntimeMenu();

// WiFi AP for demo + WiFi STA for NTP
const char* AP_SSID = "ESP32-LOGGER";
const char* AP_PASS = "12345678";

const char* WIFI_SSID = "JP";
const char* WIFI_PASS = "jio@1234";
const long GMT_OFFSET_SEC = 19800;
const int DST_OFFSET_SEC = 0;

WebServer server(80);
Preferences prefs;
const char* NVS_NAMESPACE = "logger";
const char* NVS_KEY_HASH = "finalhash";

const String ZERO_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

// logging state
enum Mode { MODE_NONE = -1, MODE_APPEND = 1, MODE_OVERWRITE = 2 };
Mode currentMode = MODE_NONE;
bool loggingEnabled = false;
unsigned long lastLog = 0;
const unsigned long LOG_INTERVAL = 5000;

// ---------------- utility: SHA256 ----------------
String sha256(String input) {
  uint8_t hash[32];
  char output[65];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  if (input.length() > 0)
    mbedtls_sha256_update(&ctx, (const unsigned char*)input.c_str(), input.length());
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);

  for (int i = 0; i < 32; ++i) sprintf(output + i*2, "%02x", hash[i]);
  output[64] = 0;
  return String(output);
}

// ---------------- time helpers ----------------
String nowTime() {
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo)) return "NO_TIME";
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &timeinfo);
  return String(buf);
}

// ---------------- file helpers ----------------
void ensureFileExists() {
  if (!SD.exists(DATA_FILE)) {
    File f = SD.open(DATA_FILE, FILE_WRITE);
    if (f) {
      f.println("datetime,temp,prev_hash,entry_hash");
      f.close();
    }
  }
}

String getLastHash() {
  if (!SD.exists(DATA_FILE)) return "";

  File f = SD.open(DATA_FILE, FILE_READ);
  if (!f) return "";
  String lastValid = "", line;
  bool skipHeader = true;
  while (f.available()) {
    line = f.readStringUntil('\n');
    line.trim();
    if (skipHeader) { skipHeader = false; continue; }
    if (line.length() > 10) lastValid = line;
  }
  f.close();

  if (lastValid == "") return "";
  int idx = lastValid.lastIndexOf(',');
  if (idx < 0) return "";
  return lastValid.substring(idx + 1);
}

// ---------------- append (protected) ----------------
void appendEntry(String tempVal) {
  String dt = nowTime();
  String prev_hash = getLastHash();
  if (prev_hash == "") prev_hash = ZERO_HASH;
  String raw = dt + "," + tempVal;
  String entry_hash = sha256(prev_hash + raw);

  File f = SD.open(DATA_FILE, FILE_APPEND);
  if (!f) {
    Serial.println("Failed to open file for append.");
    return;
  }
  f.println(raw + "," + prev_hash + "," + entry_hash);
  f.close();

  prefs.begin(NVS_NAMESPACE, false);
  prefs.putString(NVS_KEY_HASH, entry_hash);
  prefs.end();

  Serial.println("Logged: " + raw);
}

// ---------------- show file ----------------
void showFile() {
  if (!SD.exists(DATA_FILE)) {
    Serial.println("[NO FILE]");
    return;
  }
  File f = SD.open(DATA_FILE, FILE_READ);
  if (!f) { Serial.println("[CANNOT OPEN FILE]"); return; }
  Serial.println("\n----- FILE CONTENT -----");
  while (f.available()) Serial.print((char)f.read());
  f.close();
  Serial.println("\n------------------------\n");
}

// ---------------- verify chain ----------------
void verifyChain() {
  if (!SD.exists(DATA_FILE)) { Serial.println("No file!"); return; }
  File f = SD.open(DATA_FILE, FILE_READ);
  if (!f) { Serial.println("Cannot open file"); return; }

  String expected_prev = ZERO_HASH;
  String header = f.readStringUntil('\n');
  String line;
  int lineNo = 0;
  while (f.available()) {
    line = f.readStringUntil('\n');
    line.trim();
    if (line.length() < 5) continue;
    lineNo++;

    int c1 = line.indexOf(',');
    int c2 = line.indexOf(',', c1+1);
    int c3 = line.indexOf(',', c2+1);
    if (c1 < 0 || c2 < 0 || c3 < 0) { Serial.printf("TAMPERED at line %d (bad CSV)\n", lineNo); f.close(); return; }

    String dt = line.substring(0, c1);
    String temp = line.substring(c1+1, c2);
    String prev = line.substring(c2+1, c3);
    String entry = line.substring(c3+1);

    if (prev != expected_prev) {
      Serial.printf("TAMPERED at line %d (prev_hash mismatch)\n", lineNo);
      f.close();
      return;
    }

    String recomputed = sha256(prev + dt + "," + temp);
    if (recomputed != entry) {
      Serial.printf("TAMPERED at line %d (hash mismatch)\n", lineNo);
      f.close();
      return;
    }
    expected_prev = entry;
  }
  f.close();

  prefs.begin(NVS_NAMESPACE, true);
  String stored = prefs.getString(NVS_KEY_HASH, "");
  prefs.end();

  if (stored != expected_prev) {
    Serial.println("FINAL HASH mismatch → SD card cloned or old version inserted!");
    return;
  }
  Serial.println("Chain OK ✓ No tampering detected.");
}

// ---------------- reset ----------------
void resetSystem() {
  Serial.println("\n=== RESET STARTED ===");
  if (SD.exists(DATA_FILE)) {
    SD.remove(DATA_FILE);
    Serial.println("✔ data.csv deleted");
  }
  File f = SD.open(DATA_FILE, FILE_WRITE);
  if (f) {
    f.println("datetime,temp,prev_hash,entry_hash");
    f.close();
    Serial.println("✔ fresh data.csv created");
  } else {
    Serial.println("✖ failed to create data.csv");
  }

  prefs.begin(NVS_NAMESPACE, false);
  prefs.clear();
  prefs.putString(NVS_KEY_HASH, ZERO_HASH);
  prefs.end();

  Serial.println("✔ NVS reset");
  Serial.println("=== RESET COMPLETE ===");
  currentMode = MODE_NONE;
  loggingEnabled = false;
}

// ---------------- HTTP secure endpoints ----------------
void httpShow() {
  if (!SD.exists(DATA_FILE)) { server.send(200, "text/plain", "(no file)"); return; }
  File f = SD.open(DATA_FILE, FILE_READ);
  if (!f) { server.send(500, "text/plain", "(cannot open)"); return; }
  String out;
  while (f.available()) out += (char)f.read();
  f.close();
  server.send(200, "text/plain", out);
}

void httpVerify() {
  if (!SD.exists(DATA_FILE)) { server.send(200, "text/plain", "(no file)"); return; }
  File f = SD.open(DATA_FILE, FILE_READ);
  if (!f) { server.send(500, "text/plain", "(cannot open)"); return; }

  String expected_prev = ZERO_HASH;
  String header = f.readStringUntil('\n');
  int lineNo = 0;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() < 5) continue;
    lineNo++;
    int c1 = line.indexOf(',');
    int c2 = line.indexOf(',', c1+1);
    int c3 = line.indexOf(',', c2+1);
    if (c1 < 0 || c2 < 0 || c3 < 0) { f.close(); server.send(200,"text/plain","TAMPER at line "+String(lineNo)+" (bad CSV)"); return; }

    String dt = line.substring(0, c1);
    String temp = line.substring(c1+1, c2);
    String prev = line.substring(c2+1, c3);
    String entry = line.substring(c3+1);

    if (prev != expected_prev) { f.close(); server.send(200,"text/plain","TAMPER at line "+String(lineNo)+" (prev_hash mismatch)"); return; }
    String recomputed = sha256(prev + dt + "," + temp);
    if (recomputed != entry) { f.close(); server.send(200,"text/plain","TAMPER at line "+String(lineNo)+" (hash mismatch)"); return; }
    expected_prev = entry;
  }
  f.close();

  prefs.begin(NVS_NAMESPACE, true);
  String stored = prefs.getString(NVS_KEY_HASH, "");
  prefs.end();

  if (stored != expected_prev) { server.send(200,"text/plain","FINAL HASH mismatch → SD card swapped/cloned"); return; }
  server.send(200, "text/plain", "Chain OK");
}

// ---------------- ATTACK endpoints (demo) ----------------

// old simple edit (keeps placeholder format)
void httpAttackEdit() {
  if (!server.hasArg("line") || !server.hasArg("value")) {
    server.send(400, "text/plain", "usage: /attack_edit?line=N&value=XX");
    return;
  }
  int target = server.arg("line").toInt();
  String val = server.arg("value");

  File f = SD.open(DATA_FILE, FILE_READ);
  if (!f) { server.send(500,"text/plain","No file"); return; }

  String header = f.readStringUntil('\n');
  String out = header + "\n";
  int lineNo = 0;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    if (line.length() < 5) continue;
    lineNo++;
    if (lineNo == target) out += "TAMPERED," + val + ",XXX,YYY\n";
    else out += line + "\n";
  }
  f.close();

  File w = SD.open(DATA_FILE, FILE_WRITE);
  if (!w) { server.send(500,"text/plain","Write failed"); return; }
  w.print(out);
  w.close();

  server.send(200, "text/plain", "Tampered line " + String(target));
}

// New endpoint: replace a specific line with attacker-provided CSV row
void httpAttackReplace() {
  if (!server.hasArg("line") || !server.hasArg("csv")) {
    server.send(400, "text/plain", "usage: /attack_replace?line=N&csv=a,b,c,d");
    return;
  }
  int target = server.arg("line").toInt();
  String newCSV = server.arg("csv"); // WebServer decodes %20 etc.

  File f = SD.open(DATA_FILE, FILE_READ);
  if (!f) { server.send(500,"text/plain","No file"); return; }

  String header = f.readStringUntil('\n');
  String out = header + "\n";
  int lineNo = 0;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    if (line.length() < 5) continue;
    lineNo++;
    if (lineNo == target) out += newCSV + "\n";
    else out += line + "\n";
  }
  f.close();

  File w = SD.open(DATA_FILE, FILE_WRITE);
  if (!w) { server.send(500,"text/plain","Write failed"); return; }
  w.print(out);
  w.close();

  server.send(200, "text/plain", "Replaced line " + String(target));
}

// New endpoint: append arbitrary CSV row (no hashing)
void httpAttackAppendCSV() {
  if (!server.hasArg("csv")) {
    server.send(400,"text/plain","usage: /attack_append_csv?csv=a,b,c,d");
    return;
  }
  String row = server.arg("csv");
  File f = SD.open(DATA_FILE, FILE_APPEND);
  if (!f) { server.send(500,"text/plain","Append failed"); return; }
  f.println(row);
  f.close();
  server.send(200, "text/plain", "Appended forged CSV row");
}

// Append without hash protection (existing)
void httpAttackAppend() {
  if (!server.hasArg("value")) { server.send(400,"text/plain","usage: /attack_append?value=XX"); return; }
  String v = server.arg("value");
  File f = SD.open(DATA_FILE, FILE_APPEND);
  if (!f) { server.send(500,"text/plain","Append failed"); return; }
  f.println("TAMPERED," + v + ",XXX,YYY");
  f.close();
  server.send(200, "text/plain", "Tamper-append added");
}

// Overwrite whole file (existing)
void httpAttackOverwrite() {
  if (!server.hasArg("text")) { server.send(400,"text/plain","usage: /attack_overwrite?text=..."); return; }
  String content = server.arg("text");
  File f = SD.open(DATA_FILE, FILE_WRITE);
  if (!f) { server.send(500,"text/plain","Write failed"); return; }
  f.print(content);
  f.close();
  server.send(200,"text/plain","File overwritten (tampering)");
}

// ---------------- menus ----------------
void printInitMenu() {
  Serial.println("\n=== INIT MENU ===");
  Serial.println("show | append | overwrite | reset");
}
void printRuntimeMenu() {
  Serial.println("\nRuntime:");
  Serial.println("show | append <value> | stop");
}

// ---------------- setup ----------------
void setup() {
  Serial.begin(115200);
  delay(400);
  Serial.println("\nBooting ESP32 Forensic Logger...");

  // WiFi STA for NTP
  Serial.print("Connecting to WiFi");
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  unsigned long wifiStart = millis();
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(250);
    // avoid locking if no network: timeout after 20s and continue (AP still started)
    if (millis() - wifiStart > 20000) break;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\nWiFi connected");
    configTime(GMT_OFFSET_SEC, DST_OFFSET_SEC, "pool.ntp.org");
    Serial.println("Time synced");
  } else {
    Serial.println("\nWiFi not connected - proceeding (AP only)");
  }

  if (!SD.begin(SD_CS)) {
    Serial.println("SD FAILED!");
    while (1) { delay(500); Serial.print("."); } // block - SD required for this project
  }
  Serial.println("SD OK");
  ensureFileExists();

  // Start AP for HTTP access (demo)
  WiFi.softAP(AP_SSID, AP_PASS);
  Serial.println("AP SSID: ESP32-LOGGER");
  Serial.print("AP IP: "); Serial.println(WiFi.softAPIP());

  // secure endpoints
  server.on("/show", httpShow);
  server.on("/verify", httpVerify);

  // attack endpoints
  server.on("/attack_edit", httpAttackEdit);
  server.on("/attack_replace", httpAttackReplace);
  server.on("/attack_append_csv", httpAttackAppendCSV);
  server.on("/attack_append", httpAttackAppend);
  server.on("/attack_overwrite", httpAttackOverwrite);

  server.begin();

  // ensure NVS has baseline if missing
  prefs.begin(NVS_NAMESPACE, false);
  if (!prefs.isKey(NVS_KEY_HASH)) prefs.putString(NVS_KEY_HASH, ZERO_HASH);
  prefs.end();

  printInitMenu();
}

// ---------------- loop ----------------
void loop() {
  server.handleClient();

  if (loggingEnabled && millis() - lastLog > LOG_INTERVAL) {
    lastLog = millis();
    float t = random(200, 350) / 10.0;
    appendEntry(String(t, 1));
  }

  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();

    // INIT mode
    if (!loggingEnabled && currentMode == MODE_NONE) {
      if (cmd == "show") {
        showFile();
        verifyChain();
        printInitMenu();
      }
      else if (cmd == "append") {
        currentMode = MODE_APPEND;
        loggingEnabled = true;
        lastLog = millis();
        Serial.println("\nAPPEND MODE STARTED");
        printRuntimeMenu();
      }
      else if (cmd == "overwrite") {
        File f = SD.open(DATA_FILE, FILE_WRITE);
        if (f) {
          f.println("datetime,temp,prev_hash,entry_hash");
          f.close();
        }
        prefs.begin(NVS_NAMESPACE, false);
        prefs.putString(NVS_KEY_HASH, ZERO_HASH);
        prefs.end();
        Serial.println("[FILE CLEARED]");
        currentMode = MODE_OVERWRITE;
        loggingEnabled = true;
        lastLog = millis();
        Serial.println("OVERWRITE MODE STARTED");
        printRuntimeMenu();
      }
      else if (cmd == "reset") {
        resetSystem();
        printInitMenu();
      }
      else Serial.println("Invalid. Use: show | append | overwrite | reset");
    }

    // RUNTIME mode (logging)
    else {
      if (cmd == "show") {
        showFile();
        verifyChain();
      }
      else if (cmd.startsWith("append ")) {
        String v = cmd.substring(7);
        v.trim();
        if (v.length()) appendEntry(v);
        else Serial.println("Usage: append <value>");
      }
      else if (cmd == "append") {
        float t = random(200, 350) / 10.0;
        appendEntry(String(t, 1));
      }
      else if (cmd == "stop") {
        loggingEnabled = false;
        currentMode = MODE_NONE;
        Serial.println("STOPPED → INIT MENU");
        printInitMenu();
      }
      else Serial.println("Runtime: show | append <v> | stop");
    }
  }
}
