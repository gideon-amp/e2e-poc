export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export interface EncapsulationResult {
  ciphertext: string;
  sharedSecret: string;
}

export interface QuantumCryptoModuleInterface {
  generateKyberKeyPair(): Promise<KeyPair>;
  generateDilithiumKeyPair(): Promise<KeyPair>;
  kyberEncapsulate(publicKey: string): Promise<EncapsulationResult>;
  kyberDecapsulate(ciphertext: string, privateKey: string): Promise<string>;
  dilithiumSign(message: string, privateKey: string): Promise<string>;
  dilithiumVerify(
    message: string,
    signature: string,
    publicKey: string
  ): Promise<boolean>;
}

export enum QuantumCryptoError {
  KYBER_KEYGEN_ERROR = "KYBER_KEYGEN_ERROR",
  DILITHIUM_KEYGEN_ERROR = "DILITHIUM_KEYGEN_ERROR",
  KYBER_ENCAP_ERROR = "KYBER_ENCAP_ERROR",
  KYBER_DECAP_ERROR = "KYBER_DECAP_ERROR",
  DILITHIUM_SIGN_ERROR = "DILITHIUM_SIGN_ERROR",
  DILITHIUM_VERIFY_ERROR = "DILITHIUM_VERIFY_ERROR",
  MODULE_NOT_FOUND = "MODULE_NOT_FOUND",
  INVALID_INPUT = "INVALID_INPUT",
}
