import { NativeQuantumCrypto } from "../../modules/quantum-crypto/src/QuantumCrypto";
import * as SecureStore from "expo-secure-store";
import * as Crypto from "expo-crypto";
import { Buffer } from "buffer";
import "react-native-get-random-values";
import nacl from "tweetnacl";

export interface SecureContact {
  id: string;
  name: string;
  kyberPublicKey: string;
  dilithiumPublicKey: string;
  verified: boolean;
}

export interface QuantumMessage {
  id: string;
  senderId: string;
  recipientId: string;
  kyberCiphertext: string;
  encryptedPayload: string;
  nonce: string;
  signature: string;
  timestamp: number;
  version: string;
  // Debug fields to help diagnose issues
  signedData?: string;
  derivationSalt?: string;
}

export class QuantumSecureMessageService {
  private userKeys: {
    kyber: { publicKey: string; privateKey: string };
    dilithium: { publicKey: string; privateKey: string };
  } | null = null;

  private userId: string;

  constructor(userId: string) {
    this.userId = userId;
  }

  /**
   * Initialize user's quantum-resistant keys
   */
  async initializeKeys(): Promise<void> {
    try {
      // Try to load existing keys first
      const existingKeys = await this.loadExistingKeys();
      if (existingKeys) {
        this.userKeys = existingKeys;
        console.log(`Keys loaded for user ${this.userId}`);
        return;
      }

      // Generate new keys if none exist
      console.log("Generating new quantum-resistant keys...");
      const kyberKeyPair = await NativeQuantumCrypto.generateKyberKeyPair();
      const dilithiumKeyPair =
        await NativeQuantumCrypto.generateDilithiumKeyPair();

      this.userKeys = {
        kyber: kyberKeyPair,
        dilithium: dilithiumKeyPair,
      };

      // Store keys securely
      await this.storeKeys();
      console.log("Quantum-resistant keys generated and stored successfully");
    } catch (error) {
      console.error("Failed to initialize quantum keys:", error);
      throw new Error("Key initialization failed");
    }
  }

  /**
   * Get user's public keys for sharing
   */
  getPublicKeys(): { kyber: string; dilithium: string } | null {
    if (!this.userKeys) return null;

    return {
      kyber: this.userKeys.kyber.publicKey,
      dilithium: this.userKeys.dilithium.publicKey,
    };
  }

  /**
   * Encrypt and send a message
   */
  async encryptMessage(
    message: string,
    recipient: SecureContact
  ): Promise<QuantumMessage> {
    if (!this.userKeys) {
      throw new Error("User keys not initialized");
    }

    try {
      console.log(`Encrypting message from ${this.userId} to ${recipient.id}`);

      // 1. Use Kyber to establish shared secret
      const encapsulationResult = await NativeQuantumCrypto.kyberEncapsulate(
        recipient.kyberPublicKey
      );
      console.log("Kyber encapsulation successful");

      // 2. Derive symmetric key from shared secret with deterministic salt
      const derivationSalt = `${this.userId}->${recipient.id}`;
      const symmetricKey = await this.deriveSymmetricKey(
        encapsulationResult.sharedSecret,
        derivationSalt
      );
      console.log("Symmetric key derived");

      // 3. Encrypt the message with ChaCha20-Poly1305
      const { encryptedPayload, nonce } = await this.chachaEncrypt(
        message,
        symmetricKey
      );
      console.log("Symmetric encryption successful");

      // 4. Create the exact data structure that will be signed
      const timestamp = Date.now();
      const signableData = {
        kyberCiphertext: encapsulationResult.ciphertext,
        encryptedPayload,
        nonce,
        timestamp,
        senderId: this.userId,
        recipientId: recipient.id,
      };

      // 5. Create deterministic string for signing
      const messageToSign = this.createSignableMessage(signableData);
      console.log("Created signable message, length:", messageToSign.length);

      // 6. Sign with Dilithium
      const messageBase64 = Buffer.from(messageToSign, "utf8").toString(
        "base64"
      );
      const signature = await NativeQuantumCrypto.dilithiumSign(
        messageBase64,
        this.userKeys.dilithium.privateKey
      );
      console.log("Dilithium signing successful");

      const quantumMessage: QuantumMessage = {
        id: this.generateMessageId(),
        senderId: this.userId,
        recipientId: recipient.id,
        kyberCiphertext: encapsulationResult.ciphertext,
        encryptedPayload,
        nonce,
        signature,
        timestamp,
        version: "1.0.0",
        signedData: messageToSign, // Store for debugging
        derivationSalt, // Store the salt used
      };

      return quantumMessage;
    } catch (error) {
      console.error("Message encryption failed:", error);
      throw new Error("Failed to encrypt message");
    }
  }

  /**
   * Decrypt a received message
   */
  async decryptMessage(
    quantumMessage: QuantumMessage,
    sender: SecureContact
  ): Promise<string> {
    if (!this.userKeys) {
      throw new Error("User keys not initialized");
    }

    try {
      console.log(`Decrypting message from ${sender.id} to ${this.userId}`);

      // 1. Recreate the exact same signable data structure
      const signableData = {
        kyberCiphertext: quantumMessage.kyberCiphertext,
        encryptedPayload: quantumMessage.encryptedPayload,
        nonce: quantumMessage.nonce,
        timestamp: quantumMessage.timestamp,
        senderId: quantumMessage.senderId,
        recipientId: quantumMessage.recipientId,
      };

      // 2. Create the exact same deterministic string for verification
      const messageToVerify = this.createSignableMessage(signableData);
      console.log(
        "Created message for verification, length:",
        messageToVerify.length
      );

      // 3. Verify signature
      const messageBase64 = Buffer.from(messageToVerify, "utf8").toString(
        "base64"
      );
      const signatureValid = await NativeQuantumCrypto.dilithiumVerify(
        messageBase64,
        quantumMessage.signature,
        sender.dilithiumPublicKey
      );

      if (!signatureValid) {
        console.error("Signature verification failed");
        throw new Error(
          "Invalid message signature - possible tampering detected"
        );
      }
      console.log("Signature verification successful");

      // 4. Use Kyber to recover shared secret
      const sharedSecret = await NativeQuantumCrypto.kyberDecapsulate(
        quantumMessage.kyberCiphertext,
        this.userKeys.kyber.privateKey
      );
      console.log("Kyber decapsulation successful");

      // 5. Derive symmetric key using the same salt as encryption
      const derivationSalt =
        quantumMessage.derivationSalt ||
        `${quantumMessage.senderId}->${quantumMessage.recipientId}`;
      const symmetricKey = await this.deriveSymmetricKey(
        sharedSecret,
        derivationSalt
      );
      console.log("Symmetric key derived for decryption");

      // 6. Debug: Test if we can reproduce the encryption
      await this.debugSymmetricKeyDerivation(sharedSecret, derivationSalt);

      // 7. Decrypt the message payload
      const decryptedMessage = await this.chachaDecrypt(
        quantumMessage.encryptedPayload,
        symmetricKey,
        quantumMessage.nonce
      );
      console.log("Symmetric decryption successful");

      return decryptedMessage;
    } catch (error) {
      console.error("Message decryption failed:", error);
      throw new Error("Failed to decrypt message");
    }
  }

  /**
   * Derive symmetric key from shared secret using a consistent method
   */
  private async deriveSymmetricKey(
    sharedSecretBase64: string,
    salt: string
  ): Promise<Uint8Array> {
    try {
      const sharedSecretBytes = Buffer.from(sharedSecretBase64, "base64");

      console.log(`Deriving key with salt: "${salt}"`);
      console.log(`Shared secret length: ${sharedSecretBytes.length} bytes`);

      // Use a deterministic key derivation
      const saltBytes = Buffer.from(salt, "utf8");
      const info = Buffer.from("quantum-messaging-v1", "utf8");

      // Simple but consistent key derivation: SHA-256(secret + salt + info)
      const keyMaterial = Buffer.concat([sharedSecretBytes, saltBytes, info]);

      const derivedKey = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        keyMaterial.toString("base64"),
        { encoding: Crypto.CryptoEncoding.BASE64 }
      );

      const keyBytes = Buffer.from(derivedKey, "base64").slice(0, 32);
      console.log(`Derived key length: ${keyBytes.length} bytes`);

      return keyBytes;
    } catch (error) {
      console.error("Key derivation failed:", error);
      throw new Error("Failed to derive symmetric key");
    }
  }

  /**
   * Debug method to test key derivation consistency
   */
  private async debugSymmetricKeyDerivation(
    sharedSecretBase64: string,
    salt: string
  ): Promise<void> {
    try {
      console.log("🔍 Debug: Testing key derivation consistency...");

      // Derive key twice and check they match
      const key1 = await this.deriveSymmetricKey(sharedSecretBase64, salt);
      const key2 = await this.deriveSymmetricKey(sharedSecretBase64, salt);

      const key1Hex = Buffer.from(key1).toString("hex");
      const key2Hex = Buffer.from(key2).toString("hex");

      console.log(`Key 1: ${key1Hex.substring(0, 20)}...`);
      console.log(`Key 2: ${key2Hex.substring(0, 20)}...`);
      console.log(`Keys match: ${key1Hex === key2Hex ? "YES" : "NO"}`);

      if (key1Hex !== key2Hex) {
        throw new Error("Key derivation is not deterministic!");
      }
    } catch (error) {
      console.error("Key derivation debug failed:", error);
    }
  }

  /**
   * ChaCha20-Poly1305 encryption using NaCl with enhanced debugging
   */
  private async chachaEncrypt(
    message: string,
    key: Uint8Array
  ): Promise<{
    encryptedPayload: string;
    nonce: string;
  }> {
    try {
      console.log("🔒 Starting ChaCha encryption...");
      console.log(`Message length: ${message.length} characters`);
      console.log(`Key length: ${key.length} bytes`);

      const messageBytes = Buffer.from(message, "utf8");
      const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

      console.log(`Message bytes length: ${messageBytes.length}`);
      console.log(`Nonce length: ${nonce.length}`);

      // Ensure we're using exactly 32 bytes for the key
      const secretboxKey = key.slice(0, 32);
      console.log(`Using key length: ${secretboxKey.length} bytes`);

      // Use NaCl secretbox for authenticated encryption
      const encrypted = nacl.secretbox(messageBytes, nonce, secretboxKey);

      if (!encrypted) {
        throw new Error("NaCl secretbox encryption returned null");
      }

      console.log(`Encrypted length: ${encrypted.length} bytes`);

      const result = {
        encryptedPayload: Buffer.from(encrypted).toString("base64"),
        nonce: Buffer.from(nonce).toString("base64"),
      };

      console.log("✅ ChaCha encryption successful");
      return result;
    } catch (error) {
      console.error("ChaCha encryption failed:", error);
      throw new Error(`Failed to encrypt message: ${error.message}`);
    }
  }

  /**
   * ChaCha20-Poly1305 decryption using NaCl with enhanced debugging
   */
  private async chachaDecrypt(
    encryptedPayloadBase64: string,
    key: Uint8Array,
    nonceBase64: string
  ): Promise<string> {
    try {
      console.log("🔓 Starting ChaCha decryption...");
      console.log(`Key length: ${key.length} bytes`);
      console.log(
        `Encrypted payload base64 length: ${encryptedPayloadBase64.length}`
      );
      console.log(`Nonce base64 length: ${nonceBase64.length}`);

      const encryptedData = Buffer.from(encryptedPayloadBase64, "base64");
      const nonce = Buffer.from(nonceBase64, "base64");

      console.log(`Encrypted data length: ${encryptedData.length} bytes`);
      console.log(`Nonce length: ${nonce.length} bytes`);

      // Ensure we're using exactly 32 bytes for the key
      const secretboxKey = key.slice(0, 32);
      console.log(`Using key length: ${secretboxKey.length} bytes`);

      // Verify nonce length
      if (nonce.length !== nacl.secretbox.nonceLength) {
        throw new Error(
          `Invalid nonce length: ${nonce.length}, expected: ${nacl.secretbox.nonceLength}`
        );
      }

      // Use NaCl secretbox for authenticated decryption
      const decrypted = nacl.secretbox.open(
        new Uint8Array(encryptedData),
        new Uint8Array(nonce),
        secretboxKey
      );

      if (!decrypted) {
        console.error("❌ NaCl secretbox.open returned null");
        console.error("This usually means:");
        console.error("1. Wrong key");
        console.error("2. Wrong nonce");
        console.error("3. Corrupted ciphertext");
        console.error("4. Authentication tag verification failed");

        // Let's test with a simple round-trip to verify the key works
        await this.testKeyWithSimpleMessage(secretboxKey);

        throw new Error(
          "Decryption failed - authentication tag verification failed"
        );
      }

      const result = Buffer.from(decrypted).toString("utf8");
      console.log(
        `✅ ChaCha decryption successful, result length: ${result.length} characters`
      );

      return result;
    } catch (error) {
      console.error("ChaCha decryption failed:", error);
      throw new Error(`Failed to decrypt message: ${error.message}`);
    }
  }

  /**
   * Test the key with a simple round-trip to verify it's working
   */
  private async testKeyWithSimpleMessage(key: Uint8Array): Promise<void> {
    try {
      console.log("🧪 Testing key with simple round-trip...");

      const testMessage = "test";
      const messageBytes = Buffer.from(testMessage, "utf8");
      const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

      const encrypted = nacl.secretbox(messageBytes, nonce, key);
      if (!encrypted) {
        throw new Error("Test encryption failed");
      }

      const decrypted = nacl.secretbox.open(encrypted, nonce, key);
      if (!decrypted) {
        throw new Error("Test decryption failed");
      }

      const decryptedText = Buffer.from(decrypted).toString("utf8");
      if (decryptedText !== testMessage) {
        throw new Error("Test round-trip failed - messages don't match");
      }

      console.log("✅ Key test passed - the key itself is valid");
    } catch (error) {
      console.error("❌ Key test failed:", error);
      throw new Error("The derived key is invalid");
    }
  }

  /**
   * Create a consistent, deterministic message format for signing
   */
  private createSignableMessage(data: {
    kyberCiphertext: string;
    encryptedPayload: string;
    nonce: string;
    timestamp: number;
    senderId: string;
    recipientId: string;
  }): string {
    // Create a deterministic string representation
    const signableObject = {
      version: "1.0.0",
      kyberCiphertext: data.kyberCiphertext,
      encryptedPayload: data.encryptedPayload,
      nonce: data.nonce,
      timestamp: data.timestamp,
      senderId: data.senderId,
      recipientId: data.recipientId,
    };

    // Use JSON.stringify with sorted keys for deterministic output
    return JSON.stringify(signableObject, Object.keys(signableObject).sort());
  }

  /**
   * Store both private and public keys securely
   */
  private async storeKeys(): Promise<void> {
    if (!this.userKeys) return;

    const privateKeyData = {
      kyberPrivateKey: this.userKeys.kyber.privateKey,
      dilithiumPrivateKey: this.userKeys.dilithium.privateKey,
      userId: this.userId,
      created: Date.now(),
    };

    await SecureStore.setItemAsync(
      `quantum_private_keys_${this.userId}`,
      JSON.stringify(privateKeyData)
    );

    const publicKeyData = {
      kyberPublicKey: this.userKeys.kyber.publicKey,
      dilithiumPublicKey: this.userKeys.dilithium.publicKey,
      userId: this.userId,
      created: Date.now(),
    };

    await SecureStore.setItemAsync(
      `quantum_public_keys_${this.userId}`,
      JSON.stringify(publicKeyData)
    );
  }

  /**
   * Load existing keys from secure storage
   */
  private async loadExistingKeys(): Promise<typeof this.userKeys | null> {
    try {
      const [privateKeyData, publicKeyData] = await Promise.all([
        SecureStore.getItemAsync(`quantum_private_keys_${this.userId}`),
        SecureStore.getItemAsync(`quantum_public_keys_${this.userId}`),
      ]);

      if (!privateKeyData || !publicKeyData) return null;

      const privateKeys = JSON.parse(privateKeyData);
      const publicKeys = JSON.parse(publicKeyData);

      return {
        kyber: {
          publicKey: publicKeys.kyberPublicKey,
          privateKey: privateKeys.kyberPrivateKey,
        },
        dilithium: {
          publicKey: publicKeys.dilithiumPublicKey,
          privateKey: privateKeys.dilithiumPrivateKey,
        },
      };
    } catch (error) {
      console.error("Error loading existing keys:", error);
      return null;
    }
  }

  /**
   * Test the complete encryption/decryption cycle
   */
  async testEncryptDecryptCycle(
    testMessage: string = "Hello, quantum world!"
  ): Promise<boolean> {
    if (!this.userKeys) {
      throw new Error("User keys not initialized");
    }

    try {
      console.log("🧪 Testing complete encrypt/decrypt cycle...");

      // Create a mock contact (using our own keys for simplicity)
      const mockContact: SecureContact = {
        id: "test_contact",
        name: "Test Contact",
        kyberPublicKey: this.userKeys.kyber.publicKey,
        dilithiumPublicKey: this.userKeys.dilithium.publicKey,
        verified: true,
      };

      // Encrypt
      const encrypted = await this.encryptMessage(testMessage, mockContact);
      console.log("✅ Test encryption successful");

      // Decrypt
      const decrypted = await this.decryptMessage(encrypted, mockContact);
      console.log("✅ Test decryption successful");

      const success = decrypted === testMessage;
      console.log(`🔍 Cycle test result: ${success ? "PASSED" : "FAILED"}`);

      if (!success) {
        console.log(`Original: "${testMessage}"`);
        console.log(`Decrypted: "${decrypted}"`);
      }

      return success;
    } catch (error) {
      console.error("❌ Encrypt/decrypt cycle test failed:", error);
      return false;
    }
  }

  /**
   * Generate unique message ID
   */
  private generateMessageId(): string {
    return `qmsg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Clean up sensitive data from memory
   */
  clearKeys(): void {
    if (this.userKeys) {
      this.userKeys.kyber.privateKey = "";
      this.userKeys.dilithium.privateKey = "";
      this.userKeys = null;
    }
  }
}
