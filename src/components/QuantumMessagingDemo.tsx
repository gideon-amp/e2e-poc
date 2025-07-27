import React, { useState, useEffect, useRef } from "react";
import {
  View,
  Text,
  TextInput,
  Button,
  Alert,
  StyleSheet,
  ScrollView,
} from "react-native";
import {
  QuantumSecureMessageService,
  SecureContact,
  QuantumMessage,
} from "../services/QuantumSecureMessageService";
import { NativeQuantumCrypto } from "../../modules/quantum-crypto/src/QuantumCrypto";
import { Buffer } from "buffer";
import "react-native-get-random-values";

export const QuantumMessagingDemo: React.FC = () => {
  const logsScrollRef = useRef<ScrollView>(null);
  const [aliceService, setAliceService] =
    useState<QuantumSecureMessageService | null>(null);
  const [bobService, setBobService] =
    useState<QuantumSecureMessageService | null>(null);
  const [isInitialized, setIsInitialized] = useState(false);
  const [aliceKeys, setAliceKeys] = useState<{
    kyber: string;
    dilithium: string;
  } | null>(null);
  const [bobKeys, setBobKeys] = useState<{
    kyber: string;
    dilithium: string;
  } | null>(null);
  const [message, setMessage] = useState("");
  const [encryptedMessage, setEncryptedMessage] =
    useState<QuantumMessage | null>(null);
  const [decryptedMessage, setDecryptedMessage] = useState("");
  const [logs, setLogs] = useState<string[]>([]);

  const scrollToEnd = (): number =>
    requestAnimationFrame((): void =>
      logsScrollRef.current?.scrollToEnd({ animated: true })
    );

  const addLog = (message: string) => {
    console.log(message);
    setLogs((prev) => [
      ...prev,
      `${new Date().toLocaleTimeString()}: ${message}`,
    ]);
    scrollToEnd();
  };

  // Helper function to safely get buffer length
  const getBufferLength = (base64String: string): number => {
    try {
      return Buffer.from(base64String, "base64").length;
    } catch (error) {
      console.error("Failed to get buffer length:", error);
      return 0;
    }
  };

  useEffect(() => {
    initializeTwoUsers();
  }, []);

  const initializeTwoUsers = async () => {
    try {
      addLog("🚀 Initializing quantum cryptography for two users...");

      // Initialize Alice
      addLog("👩 Initializing Alice...");
      const alice = new QuantumSecureMessageService("alice_123");
      await alice.initializeKeys();
      const alicePublicKeys = alice.getPublicKeys();
      setAliceService(alice);
      setAliceKeys(alicePublicKeys);
      addLog("✅ Alice initialized successfully");

      // Initialize Bob
      addLog("👨 Initializing Bob...");
      const bob = new QuantumSecureMessageService("bob_456");
      await bob.initializeKeys();
      const bobPublicKeys = bob.getPublicKeys();
      setBobService(bob);
      setBobKeys(bobPublicKeys);
      addLog("✅ Bob initialized successfully");

      setIsInitialized(true);
      addLog("🎉 Both users ready for quantum-secure messaging!");

      Alert.alert(
        "Success",
        "Quantum-resistant cryptography initialized for both users!"
      );
    } catch (error) {
      console.error("Initialization failed:", error);
      addLog(`❌ Initialization failed: ${error.message}`);
      Alert.alert("Error", "Failed to initialize quantum cryptography");
    }
  };

  const sendMessageFromAliceToBob = async () => {
    if (!aliceService || !bobKeys || !message.trim()) {
      Alert.alert("Error", "Missing requirements for encryption");
      return;
    }

    try {
      addLog("📝 Alice preparing to send message to Bob...");

      // Create Bob's contact info for Alice
      const bobContact: SecureContact = {
        id: "bob_456",
        name: "Bob",
        kyberPublicKey: bobKeys.kyber,
        dilithiumPublicKey: bobKeys.dilithium,
        verified: true,
      };

      addLog("🔍 Validating Bob's public keys...");
      addLog(
        `📏 Bob's Kyber key length: ${getBufferLength(bobKeys.kyber)} bytes`
      );
      addLog(
        `📏 Bob's Dilithium key length: ${getBufferLength(
          bobKeys.dilithium
        )} bytes`
      );

      addLog("🔐 Encrypting message...");
      const encrypted = await aliceService.encryptMessage(
        message.trim(),
        bobContact
      );

      setEncryptedMessage(encrypted);
      addLog("✅ Message encrypted successfully!");
      addLog(`📦 Encrypted message ID: ${encrypted.id}`);

      Alert.alert(
        "Success",
        "Message encrypted with quantum-resistant algorithms!"
      );

      // Automatically try to decrypt it as Bob
      await receiveMessageAsBob(encrypted);
    } catch (error) {
      console.error("Encryption failed:", error);
      addLog(`❌ Encryption failed: ${error.message}`);
      Alert.alert("Error", `Failed to encrypt message: ${error.message}`);
    }
  };

  const receiveMessageAsBob = async (encrypted: QuantumMessage) => {
    if (!bobService || !aliceKeys) {
      Alert.alert("Error", "Bob not initialized");
      return;
    }

    try {
      addLog("📨 Bob receiving encrypted message...");

      // Create Alice's contact info for Bob
      const aliceContact: SecureContact = {
        id: "alice_123",
        name: "Alice",
        kyberPublicKey: aliceKeys.kyber,
        dilithiumPublicKey: aliceKeys.dilithium,
        verified: true,
      };

      addLog("🔓 Decrypting message...");
      const decrypted = await bobService.decryptMessage(
        encrypted,
        aliceContact
      );

      setDecryptedMessage(decrypted);
      addLog("✅ Message decrypted successfully!");
      addLog(`📄 Decrypted content: "${decrypted}"`);

      Alert.alert("Success", `Bob received: "${decrypted}"`);
    } catch (error) {
      console.error("Decryption failed:", error);
      addLog(`❌ Decryption failed: ${error.message}`);
      Alert.alert("Error", `Failed to decrypt message: ${error.message}`);
    }
  };

  const testKeyGeneration = async () => {
    try {
      addLog("🧪 Testing key generation...");

      const kyberKeys = await NativeQuantumCrypto.generateKyberKeyPair();
      const dilithiumKeys =
        await NativeQuantumCrypto.generateDilithiumKeyPair();

      addLog(
        `✅ Test Kyber keys: ${getBufferLength(
          kyberKeys.publicKey
        )} bytes public`
      );
      addLog(
        `✅ Test Dilithium keys: ${getBufferLength(
          dilithiumKeys.publicKey
        )} bytes public`
      );

      // Test encapsulation with freshly generated keys
      const encapResult = await NativeQuantumCrypto.kyberEncapsulate(
        kyberKeys.publicKey
      );
      addLog(
        `✅ Test encapsulation successful: ${getBufferLength(
          encapResult.ciphertext
        )} bytes ciphertext`
      );

      Alert.alert("Success", "Key generation test passed!");
    } catch (error) {
      console.error("Test failed:", error);
      addLog(`❌ Test failed: ${error.message}`);
      Alert.alert("Error", `Test failed: ${error.message}`);
    }
  };

  const testBufferPolyfill = () => {
    try {
      addLog("🧪 Testing Buffer polyfill...");

      // Test basic Buffer operations
      const testString = "Hello, world!";
      const buffer = Buffer.from(testString, "utf8");
      const base64 = buffer.toString("base64");
      const backToString = Buffer.from(base64, "base64").toString("utf8");

      addLog(`✅ Original: "${testString}"`);
      addLog(`✅ Base64: "${base64}"`);
      addLog(`✅ Decoded: "${backToString}"`);
      addLog(`✅ Match: ${testString === backToString ? "YES" : "NO"}`);

      if (testString === backToString) {
        Alert.alert("Success", "Buffer polyfill is working correctly!");
      } else {
        Alert.alert("Error", "Buffer polyfill test failed!");
      }
    } catch (error) {
      console.error("Buffer test failed:", error);
      addLog(`❌ Buffer test failed: ${error.message}`);
      Alert.alert("Error", `Buffer test failed: ${error.message}`);
    }
  };

  const clearLogs = () => {
    setLogs([]);
  };

  return (
    <ScrollView style={styles.container} showsVerticalScrollIndicator={false}>
      <View style={styles.containerContent}>
        <Text style={styles.title}>Quantum-Resistant Messaging Demo</Text>

        {!isInitialized ? (
          <View style={styles.loadingContainer}>
            <Text style={styles.loadingText}>
              Initializing quantum cryptography...
            </Text>
          </View>
        ) : (
          <View>
            <View style={styles.statusContainer}>
              <Text style={styles.status}>
                ✅ Alice & Bob ready for quantum-secure messaging
              </Text>
            </View>

            {aliceKeys && bobKeys && (
              <View style={styles.keyInfo}>
                <Text style={styles.subtitle}>User Keys Generated:</Text>
                <Text style={styles.keyText}>
                  👩 Alice Kyber: {aliceKeys.kyber.substring(0, 20)}... (
                  {getBufferLength(aliceKeys.kyber)} bytes)
                </Text>
                <Text style={styles.keyText}>
                  👨 Bob Kyber: {bobKeys.kyber.substring(0, 20)}... (
                  {getBufferLength(bobKeys.kyber)} bytes)
                </Text>
              </View>
            )}

            <View style={styles.buttonRow}>
              <View style={styles.buttonContainer}>
                <Button
                  title="🧪 Test Buffer"
                  onPress={testBufferPolyfill}
                  color="#6c757d"
                />
              </View>
              <View style={styles.buttonContainer}>
                <Button
                  title="🔑 Test Keys"
                  onPress={testKeyGeneration}
                  color="#007AFF"
                />
              </View>
            </View>

            <View style={styles.messageSection}>
              <Text style={styles.subtitle}>Send Message (Alice → Bob):</Text>
              <TextInput
                style={styles.input}
                value={message}
                onChangeText={setMessage}
                placeholder="Enter message for Alice to send to Bob..."
                multiline
              />
              <Button
                title="🔐 Encrypt & Send"
                onPress={sendMessageFromAliceToBob}
                disabled={!message.trim()}
                color="#28a745"
              />
            </View>

            {encryptedMessage && (
              <View style={styles.encryptedSection}>
                <Text style={styles.subtitle}>Encrypted Message:</Text>
                <Text style={styles.encryptedText}>
                  ID: {encryptedMessage.id}
                </Text>
                <Text style={styles.encryptedText}>
                  Ciphertext:{" "}
                  {encryptedMessage.kyberCiphertext.substring(0, 30)}
                  ...
                </Text>
                <Text style={styles.encryptedText}>
                  Payload: {encryptedMessage.encryptedPayload.substring(0, 30)}
                  ...
                </Text>
              </View>
            )}

            {decryptedMessage && (
              <View style={styles.decryptedSection}>
                <Text style={styles.subtitle}>✅ Bob Received:</Text>
                <Text style={styles.decryptedText}>"{decryptedMessage}"</Text>
              </View>
            )}

            <View style={styles.logsSection}>
              <View style={styles.logsHeader}>
                <Text style={styles.subtitle}>Debug Logs:</Text>
                <Button title="Clear" onPress={clearLogs} color="#dc3545" />
              </View>
              <ScrollView
                ref={logsScrollRef}
                style={styles.logsContainer}
                nestedScrollEnabled
                showsVerticalScrollIndicator={false}
              >
                {logs.map((log, index) => (
                  <Text key={index} style={styles.logText}>
                    {log}
                  </Text>
                ))}
              </ScrollView>
            </View>
          </View>
        )}
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#f5f5f5",
  },
  containerContent: {
    padding: 10,
  },
  title: {
    fontSize: 24,
    fontWeight: "bold",
    marginBottom: 20,
    textAlign: "center",
    color: "#333",
  },
  loadingContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    paddingVertical: 50,
  },
  loadingText: {
    fontSize: 16,
    color: "#666",
  },
  statusContainer: {
    backgroundColor: "#d4edda",
    padding: 15,
    borderRadius: 8,
    marginBottom: 20,
    borderColor: "#c3e6cb",
    borderWidth: 1,
  },
  status: {
    fontSize: 16,
    color: "#155724",
    textAlign: "center",
    fontWeight: "500",
  },
  keyInfo: {
    backgroundColor: "white",
    padding: 15,
    borderRadius: 8,
    marginBottom: 20,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  subtitle: {
    fontSize: 18,
    fontWeight: "bold",
    marginBottom: 10,
    color: "#333",
  },
  keyText: {
    fontSize: 12,
    fontFamily: "monospace",
    marginBottom: 5,
    color: "#666",
    backgroundColor: "#f8f9fa",
    padding: 5,
    borderRadius: 4,
  },
  buttonRow: {
    flexDirection: "row",
    marginBottom: 15,
    justifyContent: "space-between",
  },
  buttonContainer: {
    flex: 1,
    marginHorizontal: 5,
  },
  messageSection: {
    backgroundColor: "white",
    padding: 15,
    borderRadius: 8,
    marginBottom: 20,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  input: {
    borderWidth: 1,
    borderColor: "#ddd",
    borderRadius: 8,
    padding: 12,
    marginBottom: 15,
    minHeight: 80,
    textAlignVertical: "top",
    backgroundColor: "#f8f9fa",
  },
  encryptedSection: {
    backgroundColor: "#fff3cd",
    padding: 15,
    borderRadius: 8,
    marginBottom: 20,
    borderColor: "#ffeaa7",
    borderWidth: 1,
  },
  encryptedText: {
    fontSize: 12,
    fontFamily: "monospace",
    marginBottom: 5,
    color: "#856404",
  },
  decryptedSection: {
    backgroundColor: "#d4edda",
    padding: 15,
    borderRadius: 8,
    marginBottom: 20,
    borderColor: "#c3e6cb",
    borderWidth: 1,
  },
  decryptedText: {
    fontSize: 16,
    fontStyle: "italic",
    color: "#155724",
    fontWeight: "500",
  },
  logsSection: {
    backgroundColor: "white",
    borderRadius: 8,
    marginBottom: 20,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  logsHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    padding: 15,
    borderBottomWidth: 1,
    borderBottomColor: "#eee",
  },
  logsContainer: {
    maxHeight: 200,
    padding: 10,
  },
  logText: {
    fontSize: 11,
    fontFamily: "monospace",
    marginBottom: 2,
    color: "#666",
  },
});

export default QuantumMessagingDemo;
