import ExpoModulesCore
import Foundation
import Security
import CommonCrypto

public class QuantumCryptoModule: Module {
  public func definition() -> ModuleDefinition {
    Name("QuantumCrypto")

    AsyncFunction("generateKyberKeyPair") { (promise: Promise) in
      DispatchQueue.global(qos: .userInitiated).async {
        do {
          let result = try self.generateKyberKeyPairNative()
          promise.resolve(result)
        } catch {
          print("Kyber key generation error: \(error)")
          promise.reject("KYBER_KEYGEN_ERROR", "Failed to generate Kyber key pair: \(error.localizedDescription)")
        }
      }
    }

    AsyncFunction("generateDilithiumKeyPair") { (promise: Promise) in
      DispatchQueue.global(qos: .userInitiated).async {
        do {
          let result = try self.generateDilithiumKeyPairNative()
          promise.resolve(result)
        } catch {
          print("Dilithium key generation error: \(error)")
          promise.reject("DILITHIUM_KEYGEN_ERROR", "Failed to generate Dilithium key pair: \(error.localizedDescription)")
        }
      }
    }

    AsyncFunction("kyberEncapsulate") { (publicKeyBase64: String, promise: Promise) in
      DispatchQueue.global(qos: .userInitiated).async {
        do {
          print("Attempting Kyber encapsulation with public key: \(publicKeyBase64.prefix(20))...")
          
          guard let publicKeyData = Data(base64Encoded: publicKeyBase64) else {
            print("Failed to decode base64 public key")
            throw QuantumCryptoError.invalidPublicKey
          }
          
          print("Public key data length: \(publicKeyData.count), expected: \(OQS_KEM_kyber_768_length_public_key)")
          
          // Validate public key length
          guard publicKeyData.count == OQS_KEM_kyber_768_length_public_key else {
            print("Invalid public key length: \(publicKeyData.count), expected: \(OQS_KEM_kyber_768_length_public_key)")
            throw QuantumCryptoError.invalidPublicKeyLength
          }
          
          let result = try self.kyberEncapsulateNative(publicKey: publicKeyData)
          print("Kyber encapsulation successful")
          promise.resolve(result)
        } catch let error as QuantumCryptoError {
          print("Kyber encapsulation error: \(error)")
          promise.reject("KYBER_ENCAP_ERROR", "Error: \(error.localizedDescription)")
        } catch {
          print("Unexpected Kyber encapsulation error: \(error)")
          promise.reject("KYBER_ENCAP_ERROR", "Error: \(error.localizedDescription)")
        }
      }
    }

    AsyncFunction("kyberDecapsulate") { (ciphertextBase64: String, privateKeyBase64: String, promise: Promise) in
      DispatchQueue.global(qos: .userInitiated).async {
        do {
          guard let ciphertextData = Data(base64Encoded: ciphertextBase64),
                let privateKeyData = Data(base64Encoded: privateKeyBase64) else {
            throw QuantumCryptoError.invalidInput
          }
          
          // Validate input lengths
          guard ciphertextData.count == OQS_KEM_kyber_768_length_ciphertext else {
            throw QuantumCryptoError.invalidCiphertextLength
          }
          
          guard privateKeyData.count == OQS_KEM_kyber_768_length_secret_key else {
            throw QuantumCryptoError.invalidPrivateKeyLength
          }
          
          let sharedSecret = try self.kyberDecapsulateNative(ciphertext: ciphertextData, privateKey: privateKeyData)
          promise.resolve(sharedSecret.base64EncodedString())
        } catch {
          print("Kyber decapsulation error: \(error)")
          promise.reject("KYBER_DECAP_ERROR", "Failed to perform Kyber decapsulation: \(error.localizedDescription)")
        }
      }
    }

    AsyncFunction("dilithiumSign") { (messageBase64: String, privateKeyBase64: String, promise: Promise) in
      DispatchQueue.global(qos: .userInitiated).async {
        do {
          guard let messageData = Data(base64Encoded: messageBase64),
                let privateKeyData = Data(base64Encoded: privateKeyBase64) else {
            throw QuantumCryptoError.invalidInput
          }
          
          // Validate private key length
          guard privateKeyData.count == OQS_SIG_dilithium_3_length_secret_key else {
            throw QuantumCryptoError.invalidPrivateKeyLength
          }
          
          let signature = try self.dilithiumSignNative(message: messageData, privateKey: privateKeyData)
          promise.resolve(signature.base64EncodedString())
        } catch {
          print("Dilithium signing error: \(error)")
          promise.reject("DILITHIUM_SIGN_ERROR", "Failed to sign with Dilithium: \(error.localizedDescription)")
        }
      }
    }

    AsyncFunction("dilithiumVerify") { (messageBase64: String, signatureBase64: String, publicKeyBase64: String, promise: Promise) in
      DispatchQueue.global(qos: .userInitiated).async {
        do {
          guard let messageData = Data(base64Encoded: messageBase64),
                let signatureData = Data(base64Encoded: signatureBase64),
                let publicKeyData = Data(base64Encoded: publicKeyBase64) else {
            throw QuantumCryptoError.invalidInput
          }
          
          // Validate public key length
          guard publicKeyData.count == OQS_SIG_dilithium_3_length_public_key else {
            throw QuantumCryptoError.invalidPublicKeyLength
          }
          
          let isValid = try self.dilithiumVerifyNative(message: messageData, signature: signatureData, publicKey: publicKeyData)
          promise.resolve(isValid)
        } catch {
          print("Dilithium verification error: \(error)")
          promise.reject("DILITHIUM_VERIFY_ERROR", "Failed to verify Dilithium signature: \(error.localizedDescription)")
        }
      }
    }
  }

  // MARK: - Native Implementation Methods
  
  private func generateKyberKeyPairNative() throws -> [String: String] {
    var publicKey = [UInt8](repeating: 0, count: Int(OQS_KEM_kyber_768_length_public_key))
    var privateKey = [UInt8](repeating: 0, count: Int(OQS_KEM_kyber_768_length_secret_key))
    
    let result = OQS_KEM_kyber_768_keypair(&publicKey, &privateKey)
    print("Kyber keypair generation result: \(result)")
    
    guard result == OQS_SUCCESS else {
      throw QuantumCryptoError.keyGenerationFailed
    }
    
    let publicKeyData = Data(publicKey)
    let privateKeyData = Data(privateKey)
    
    print("Generated Kyber keys - Public: \(publicKeyData.count) bytes, Private: \(privateKeyData.count) bytes")
    
    return [
      "publicKey": publicKeyData.base64EncodedString(),
      "privateKey": privateKeyData.base64EncodedString()
    ]
  }
  
  private func generateDilithiumKeyPairNative() throws -> [String: String] {
    var publicKey = [UInt8](repeating: 0, count: Int(OQS_SIG_dilithium_3_length_public_key))
    var privateKey = [UInt8](repeating: 0, count: Int(OQS_SIG_dilithium_3_length_secret_key))
    
    let result = OQS_SIG_dilithium_3_keypair(&publicKey, &privateKey)
    print("Dilithium keypair generation result: \(result)")
    
    guard result == OQS_SUCCESS else {
      throw QuantumCryptoError.keyGenerationFailed
    }
    
    let publicKeyData = Data(publicKey)
    let privateKeyData = Data(privateKey)
    
    print("Generated Dilithium keys - Public: \(publicKeyData.count) bytes, Private: \(privateKeyData.count) bytes")
    
    return [
      "publicKey": publicKeyData.base64EncodedString(),
      "privateKey": privateKeyData.base64EncodedString()
    ]
  }
  
  private func kyberEncapsulateNative(publicKey: Data) throws -> [String: String] {
    print("Starting Kyber encapsulation...")
    
    var ciphertext = [UInt8](repeating: 0, count: Int(OQS_KEM_kyber_768_length_ciphertext))
    var sharedSecret = [UInt8](repeating: 0, count: Int(OQS_KEM_kyber_768_length_shared_secret))
    
    let result = publicKey.withUnsafeBytes { publicKeyBytes in
      guard let publicKeyPtr = publicKeyBytes.bindMemory(to: UInt8.self).baseAddress else {
        print("Failed to get public key pointer")
        return OQS_ERROR
      }
      
      print("Calling OQS_KEM_kyber_768_encaps...")
      let encapResult = OQS_KEM_kyber_768_encaps(&ciphertext, &sharedSecret, publicKeyPtr)
      print("OQS_KEM_kyber_768_encaps result: \(encapResult)")
      return encapResult
    }
    
    guard result == OQS_SUCCESS else {
      print("Kyber encapsulation failed with result: \(result)")
      throw QuantumCryptoError.encapsulationFailed
    }
    
    let ciphertextData = Data(ciphertext)
    let sharedSecretData = Data(sharedSecret)
    
    print("Encapsulation successful - Ciphertext: \(ciphertextData.count) bytes, SharedSecret: \(sharedSecretData.count) bytes")
    
    return [
      "ciphertext": ciphertextData.base64EncodedString(),
      "sharedSecret": sharedSecretData.base64EncodedString()
    ]
  }
  
  private func kyberDecapsulateNative(ciphertext: Data, privateKey: Data) throws -> Data {
    print("Starting Kyber decapsulation...")
    
    var sharedSecret = [UInt8](repeating: 0, count: Int(OQS_KEM_kyber_768_length_shared_secret))
    
    let result = ciphertext.withUnsafeBytes { ciphertextBytes in
      privateKey.withUnsafeBytes { privateKeyBytes in
        guard let ciphertextPtr = ciphertextBytes.bindMemory(to: UInt8.self).baseAddress,
              let privateKeyPtr = privateKeyBytes.bindMemory(to: UInt8.self).baseAddress else {
          print("Failed to get pointers for decapsulation")
          return OQS_ERROR
        }
        
        print("Calling OQS_KEM_kyber_768_decaps...")
        let decapResult = OQS_KEM_kyber_768_decaps(&sharedSecret, ciphertextPtr, privateKeyPtr)
        print("OQS_KEM_kyber_768_decaps result: \(decapResult)")
        return decapResult
      }
    }
    
    guard result == OQS_SUCCESS else {
      print("Kyber decapsulation failed with result: \(result)")
      throw QuantumCryptoError.decapsulationFailed
    }
    
    let sharedSecretData = Data(sharedSecret)
    print("Decapsulation successful - SharedSecret: \(sharedSecretData.count) bytes")
    
    return sharedSecretData
  }
  
  private func dilithiumSignNative(message: Data, privateKey: Data) throws -> Data {
    print("Starting Dilithium signing...")
    
    var signature = [UInt8](repeating: 0, count: Int(OQS_SIG_dilithium_3_length_signature))
    var signatureLength = 0
    
    let result = message.withUnsafeBytes { messageBytes in
      privateKey.withUnsafeBytes { privateKeyBytes in
        guard let messagePtr = messageBytes.bindMemory(to: UInt8.self).baseAddress,
              let privateKeyPtr = privateKeyBytes.bindMemory(to: UInt8.self).baseAddress else {
          print("Failed to get pointers for signing")
          return OQS_ERROR
        }
        
        print("Calling OQS_SIG_dilithium_3_sign...")
        let signResult = OQS_SIG_dilithium_3_sign(&signature, &signatureLength, messagePtr, message.count, privateKeyPtr)
        print("OQS_SIG_dilithium_3_sign result: \(signResult), signature length: \(signatureLength)")
        return signResult
      }
    }
    
    guard result == OQS_SUCCESS else {
      print("Dilithium signing failed with result: \(result)")
      throw QuantumCryptoError.signingFailed
    }
    
    let signatureData = Data(signature.prefix(signatureLength))
    print("Signing successful - Signature: \(signatureData.count) bytes")
    
    return signatureData
  }
  
  private func dilithiumVerifyNative(message: Data, signature: Data, publicKey: Data) throws -> Bool {
    print("Starting Dilithium verification...")
    
    let result = message.withUnsafeBytes { messageBytes in
      signature.withUnsafeBytes { signatureBytes in
        publicKey.withUnsafeBytes { publicKeyBytes in
          guard let messagePtr = messageBytes.bindMemory(to: UInt8.self).baseAddress,
                let signaturePtr = signatureBytes.bindMemory(to: UInt8.self).baseAddress,
                let publicKeyPtr = publicKeyBytes.bindMemory(to: UInt8.self).baseAddress else {
            print("Failed to get pointers for verification")
            return OQS_ERROR
          }
          
          print("Calling OQS_SIG_dilithium_3_verify...")
          let verifyResult = OQS_SIG_dilithium_3_verify(messagePtr, message.count, signaturePtr, signature.count, publicKeyPtr)
          print("OQS_SIG_dilithium_3_verify result: \(verifyResult)")
          return verifyResult
        }
      }
    }
    
    let isValid = result == OQS_SUCCESS
    print("Verification result: \(isValid)")
    
    return isValid
  }
}

enum QuantumCryptoError: Error, LocalizedError {
  case invalidPublicKey
  case invalidInput
  case keyGenerationFailed
  case encapsulationFailed
  case decapsulationFailed
  case signingFailed
  case verificationFailed
  case invalidPublicKeyLength
  case invalidPrivateKeyLength
  case invalidCiphertextLength
  
  var errorDescription: String? {
    switch self {
    case .invalidPublicKey:
      return "Invalid or malformed public key"
    case .invalidInput:
      return "Invalid input parameters"
    case .keyGenerationFailed:
      return "Failed to generate cryptographic keys"
    case .encapsulationFailed:
      return "Failed to perform key encapsulation"
    case .decapsulationFailed:
      return "Failed to perform key decapsulation"
    case .signingFailed:
      return "Failed to create digital signature"
    case .verificationFailed:
      return "Failed to verify digital signature"
    case .invalidPublicKeyLength:
      return "Public key has incorrect length"
    case .invalidPrivateKeyLength:
      return "Private key has incorrect length"
    case .invalidCiphertextLength:
      return "Ciphertext has incorrect length"
    }
  }
}
