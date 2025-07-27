import QuantumCryptoModule from "./QuantumCryptoModule";
import {
  KeyPair,
  EncapsulationResult,
  QuantumCryptoError,
} from "./QuantumCrypto.types";

export class NativeQuantumCrypto {
  /**
   * Generate a Kyber key pair for key encapsulation mechanism
   */
  static async generateKyberKeyPair(): Promise<KeyPair> {
    try {
      return await QuantumCryptoModule.generateKyberKeyPair();
    } catch (error) {
      throw new Error(`${QuantumCryptoError.KYBER_KEYGEN_ERROR}: ${error}`);
    }
  }

  /**
   * Generate a Dilithium key pair for digital signatures
   */
  static async generateDilithiumKeyPair(): Promise<KeyPair> {
    try {
      return await QuantumCryptoModule.generateDilithiumKeyPair();
    } catch (error) {
      throw new Error(`${QuantumCryptoError.DILITHIUM_KEYGEN_ERROR}: ${error}`);
    }
  }

  /**
   * Perform Kyber encapsulation to create shared secret
   */
  static async kyberEncapsulate(
    publicKey: string
  ): Promise<EncapsulationResult> {
    try {
      if (!publicKey || typeof publicKey !== "string") {
        throw new Error("Invalid public key provided");
      }
      return await QuantumCryptoModule.kyberEncapsulate(publicKey);
    } catch (error) {
      throw new Error(`${QuantumCryptoError.KYBER_ENCAP_ERROR}: ${error}`);
    }
  }

  /**
   * Perform Kyber decapsulation to recover shared secret
   */
  static async kyberDecapsulate(
    ciphertext: string,
    privateKey: string
  ): Promise<string> {
    try {
      if (
        !ciphertext ||
        !privateKey ||
        typeof ciphertext !== "string" ||
        typeof privateKey !== "string"
      ) {
        throw new Error("Invalid ciphertext or private key provided");
      }
      return await QuantumCryptoModule.kyberDecapsulate(ciphertext, privateKey);
    } catch (error) {
      throw new Error(`${QuantumCryptoError.KYBER_DECAP_ERROR}: ${error}`);
    }
  }

  /**
   * Sign a message using Dilithium
   */
  static async dilithiumSign(
    message: string,
    privateKey: string
  ): Promise<string> {
    try {
      if (
        !message ||
        !privateKey ||
        typeof message !== "string" ||
        typeof privateKey !== "string"
      ) {
        throw new Error("Invalid message or private key provided");
      }

      // Convert message to base64 for native processing
      const messageBase64 = Buffer.from(message, "utf8").toString("base64");
      return await QuantumCryptoModule.dilithiumSign(messageBase64, privateKey);
    } catch (error) {
      throw new Error(`${QuantumCryptoError.DILITHIUM_SIGN_ERROR}: ${error}`);
    }
  }

  /**
   * Verify a Dilithium signature
   */
  static async dilithiumVerify(
    message: string,
    signature: string,
    publicKey: string
  ): Promise<boolean> {
    try {
      if (
        !message ||
        !signature ||
        !publicKey ||
        typeof message !== "string" ||
        typeof signature !== "string" ||
        typeof publicKey !== "string"
      ) {
        throw new Error("Invalid message, signature, or public key provided");
      }

      // Convert message to base64 for native processing
      const messageBase64 = Buffer.from(message, "utf8").toString("base64");
      return await QuantumCryptoModule.dilithiumVerify(
        messageBase64,
        signature,
        publicKey
      );
    } catch (error) {
      throw new Error(`${QuantumCryptoError.DILITHIUM_VERIFY_ERROR}: ${error}`);
    }
  }

  /**
   * Check if the native module is available
   */
  static isAvailable(): boolean {
    try {
      return QuantumCryptoModule !== null && QuantumCryptoModule !== undefined;
    } catch {
      return false;
    }
  }
}

export * from "./QuantumCrypto.types";
export { QuantumCryptoModule };
