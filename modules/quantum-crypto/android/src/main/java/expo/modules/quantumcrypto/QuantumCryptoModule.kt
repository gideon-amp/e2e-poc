package expo.modules.quantumcrypto

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.Promise
import java.security.Security
import java.security.SecureRandom
import android.util.Base64
import android.util.Log
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.crypto.crystals.kyber.*
import org.bouncycastle.pqc.crypto.crystals.dilithium.*
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import expo.modules.kotlin.functions.Coroutine

class QuantumCryptoModule : Module() {
  
  companion object {
    private const val TAG = "QuantumCryptoModule"
    
    // Expected key and data lengths for validation
    private const val KYBER_768_PUBLIC_KEY_LENGTH = 1184
    private const val KYBER_768_PRIVATE_KEY_LENGTH = 2400
    private const val KYBER_768_CIPHERTEXT_LENGTH = 1088
    private const val KYBER_768_SHARED_SECRET_LENGTH = 32
    
    private const val DILITHIUM_3_PUBLIC_KEY_LENGTH = 1952
    private const val DILITHIUM_3_PRIVATE_KEY_LENGTH = 4000
    
    init {
      // Ensure BouncyCastle provider is installed
      if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
        Security.addProvider(BouncyCastleProvider())
        Log.d(TAG, "BouncyCastle provider added")
      } else {
        Log.d(TAG, "BouncyCastle provider already available")
      }
    }
  }

  // Store key pairs to avoid reconstruction issues
  private val kyberKeyPairs = mutableMapOf<String, AsymmetricCipherKeyPair>()
  private val dilithiumKeyPairs = mutableMapOf<String, AsymmetricCipherKeyPair>()

  override fun definition() = ModuleDefinition {
    Name("QuantumCrypto")

    AsyncFunction("generateKyberKeyPair") Coroutine { promise: Promise ->
      withContext(Dispatchers.Default) {
        try {
          Log.d(TAG, "Starting Kyber key pair generation...")
          
          val keyPairGenerator = KyberKeyPairGenerator()
          keyPairGenerator.init(KyberKeyGenerationParameters(SecureRandom(), KyberParameters.kyber768))
          
          val keyPair = keyPairGenerator.generateKeyPair()
          val publicKey = (keyPair.public as KyberPublicKeyParameters).encoded
          val privateKey = (keyPair.private as KyberPrivateKeyParameters).encoded
          
          Log.d(TAG, "Kyber key generation successful")
          Log.d(TAG, "Generated Kyber keys - Public: ${publicKey.size} bytes, Private: ${privateKey.size} bytes")
          
          // Store the key pair for later use
          val keyId = Base64.encodeToString(publicKey, Base64.NO_WRAP)
          kyberKeyPairs[keyId] = keyPair
          
          val result = mapOf(
            "publicKey" to Base64.encodeToString(publicKey, Base64.NO_WRAP),
            "privateKey" to Base64.encodeToString(privateKey, Base64.NO_WRAP)
          )
          
          promise.resolve(result)
        } catch (e: Exception) {
          Log.e(TAG, "Kyber key generation failed", e)
          promise.reject("KYBER_KEYGEN_ERROR", "Failed to generate Kyber key pair: ${e.message}", e)
        }
      }
    }

    AsyncFunction("generateDilithiumKeyPair") Coroutine { promise: Promise ->
      withContext(Dispatchers.Default) {
        try {
          Log.d(TAG, "Starting Dilithium key pair generation...")
          
          val keyPairGenerator = DilithiumKeyPairGenerator()
          keyPairGenerator.init(DilithiumKeyGenerationParameters(SecureRandom(), DilithiumParameters.dilithium3))
          
          val keyPair = keyPairGenerator.generateKeyPair()
          val publicKey = (keyPair.public as DilithiumPublicKeyParameters).encoded
          val privateKey = (keyPair.private as DilithiumPrivateKeyParameters).encoded
          
          Log.d(TAG, "Dilithium key generation successful")
          Log.d(TAG, "Generated Dilithium keys - Public: ${publicKey.size} bytes, Private: ${privateKey.size} bytes")
          
          // Store the key pair for later use
          val keyId = Base64.encodeToString(publicKey, Base64.NO_WRAP)
          dilithiumKeyPairs[keyId] = keyPair
          
          val result = mapOf(
            "publicKey" to Base64.encodeToString(publicKey, Base64.NO_WRAP),
            "privateKey" to Base64.encodeToString(privateKey, Base64.NO_WRAP)
          )
          
          promise.resolve(result)
        } catch (e: Exception) {
          Log.e(TAG, "Dilithium key generation failed", e)
          promise.reject("DILITHIUM_KEYGEN_ERROR", "Failed to generate Dilithium key pair: ${e.message}", e)
        }
      }
    }

    AsyncFunction("kyberEncapsulate") Coroutine { publicKeyBase64: String, promise: Promise ->
      withContext(Dispatchers.Default) {
        try {
          Log.d(TAG, "Starting Kyber encapsulation...")
          
          val publicKeyBytes = try {
            Base64.decode(publicKeyBase64, Base64.NO_WRAP)
          } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid base64 public key: ${e.message}")
          }
          
          Log.d(TAG, "Public key data length: ${publicKeyBytes.size}")
          
          val publicKey = try {
            // Try to use stored key pair first
            val storedKeyPair = kyberKeyPairs[publicKeyBase64]
            if (storedKeyPair != null) {
              storedKeyPair.public as KyberPublicKeyParameters
            } else {
              // Reconstruct from bytes - this is a simplified approach
              // In practice, you might need a more sophisticated reconstruction
              KyberPublicKeyParameters(KyberParameters.kyber768, publicKeyBytes)
            }
          } catch (e: Exception) {
            throw IllegalArgumentException("Failed to parse Kyber public key: ${e.message}")
          }
          
          val kemGenerator = KyberKEMGenerator(SecureRandom())
          val kemEncapsulation = kemGenerator.generateEncapsulated(publicKey)
          
          Log.d(TAG, "Kyber encapsulation successful")
          Log.d(TAG, "Ciphertext: ${kemEncapsulation.encapsulation.size} bytes, SharedSecret: ${kemEncapsulation.secret.size} bytes")
          
          val result = mapOf(
            "ciphertext" to Base64.encodeToString(kemEncapsulation.encapsulation, Base64.NO_WRAP),
            "sharedSecret" to Base64.encodeToString(kemEncapsulation.secret, Base64.NO_WRAP)
          )
          
          promise.resolve(result)
        } catch (e: IllegalArgumentException) {
          Log.e(TAG, "Invalid input for Kyber encapsulation", e)
          promise.reject("KYBER_ENCAP_ERROR", "Invalid input: ${e.message}", e)
        } catch (e: Exception) {
          Log.e(TAG, "Kyber encapsulation failed", e)
          promise.reject("KYBER_ENCAP_ERROR", "Failed to perform Kyber encapsulation: ${e.message}", e)
        }
      }
    }

    AsyncFunction("kyberDecapsulate") Coroutine { ciphertextBase64: String, privateKeyBase64: String, promise: Promise ->
      withContext(Dispatchers.Default) {
        try {
          Log.d(TAG, "Starting Kyber decapsulation...")
          
          val ciphertextBytes = try {
            Base64.decode(ciphertextBase64, Base64.NO_WRAP)
          } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid base64 ciphertext: ${e.message}")
          }
          
          val privateKeyBytes = try {
            Base64.decode(privateKeyBase64, Base64.NO_WRAP)
          } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid base64 private key: ${e.message}")
          }
          
          Log.d(TAG, "Ciphertext length: ${ciphertextBytes.size}, Private key length: ${privateKeyBytes.size}")
          
          // Find the corresponding key pair by checking all stored pairs
          var privateKey: KyberPrivateKeyParameters? = null
          for ((publicKeyBase64, keyPair) in kyberKeyPairs) {
            val storedPrivateKey = keyPair.private as KyberPrivateKeyParameters
            if (storedPrivateKey.encoded.contentEquals(privateKeyBytes)) {
              privateKey = storedPrivateKey
              break
            }
          }
          
          if (privateKey == null) {
            throw IllegalArgumentException("Private key not found in stored key pairs")
          }
          
          val kemExtractor = KyberKEMExtractor(privateKey)
          val sharedSecret = kemExtractor.extractSecret(ciphertextBytes)
          
          Log.d(TAG, "Kyber decapsulation successful")
          Log.d(TAG, "SharedSecret: ${sharedSecret.size} bytes")
          
          val result = Base64.encodeToString(sharedSecret, Base64.NO_WRAP)
          promise.resolve(result)
        } catch (e: IllegalArgumentException) {
          Log.e(TAG, "Invalid input for Kyber decapsulation", e)
          promise.reject("KYBER_DECAP_ERROR", "Invalid input: ${e.message}", e)
        } catch (e: Exception) {
          Log.e(TAG, "Kyber decapsulation failed", e)
          promise.reject("KYBER_DECAP_ERROR", "Failed to perform Kyber decapsulation: ${e.message}", e)
        }
      }
    }

    AsyncFunction("dilithiumSign") Coroutine { messageBase64: String, privateKeyBase64: String, promise: Promise ->
      withContext(Dispatchers.Default) {
        try {
          Log.d(TAG, "Starting Dilithium signing...")
          
          val messageBytes = try {
            Base64.decode(messageBase64, Base64.NO_WRAP)
          } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid base64 message: ${e.message}")
          }
          
          val privateKeyBytes = try {
            Base64.decode(privateKeyBase64, Base64.NO_WRAP)
          } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid base64 private key: ${e.message}")
          }
          
          Log.d(TAG, "Message length: ${messageBytes.size}, Private key length: ${privateKeyBytes.size}")
          
          // Find the corresponding key pair by checking all stored pairs
          var privateKey: DilithiumPrivateKeyParameters? = null
          for ((publicKeyBase64, keyPair) in dilithiumKeyPairs) {
            val storedPrivateKey = keyPair.private as DilithiumPrivateKeyParameters
            if (storedPrivateKey.encoded.contentEquals(privateKeyBytes)) {
              privateKey = storedPrivateKey
              break
            }
          }
          
          if (privateKey == null) {
            throw IllegalArgumentException("Private key not found in stored key pairs")
          }
          
          val signer = DilithiumSigner()
          signer.init(true, privateKey)
          val signature = signer.generateSignature(messageBytes)
          
          Log.d(TAG, "Dilithium signing successful")
          Log.d(TAG, "Signature: ${signature.size} bytes")
          
          val result = Base64.encodeToString(signature, Base64.NO_WRAP)
          promise.resolve(result)
        } catch (e: IllegalArgumentException) {
          Log.e(TAG, "Invalid input for Dilithium signing", e)
          promise.reject("DILITHIUM_SIGN_ERROR", "Invalid input: ${e.message}", e)
        } catch (e: Exception) {
          Log.e(TAG, "Dilithium signing failed", e)
          promise.reject("DILITHIUM_SIGN_ERROR", "Failed to sign with Dilithium: ${e.message}", e)
        }
      }
    }

    AsyncFunction("dilithiumVerify") Coroutine { messageBase64: String, signatureBase64: String, publicKeyBase64: String, promise: Promise ->
      withContext(Dispatchers.Default) {
        try {
          Log.d(TAG, "Starting Dilithium verification...")
          
          val messageBytes = try {
            Base64.decode(messageBase64, Base64.NO_WRAP)
          } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid base64 message: ${e.message}")
          }
          
          val signatureBytes = try {
            Base64.decode(signatureBase64, Base64.NO_WRAP)
          } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid base64 signature: ${e.message}")
          }
          
          val publicKeyBytes = try {
            Base64.decode(publicKeyBase64, Base64.NO_WRAP)
          } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid base64 public key: ${e.message}")
          }
          
          Log.d(TAG, "Message: ${messageBytes.size} bytes, Signature: ${signatureBytes.size} bytes, Public key: ${publicKeyBytes.size} bytes")
          
          val publicKey = try {
            // Try to use stored key pair first
            val storedKeyPair = dilithiumKeyPairs[publicKeyBase64]
            if (storedKeyPair != null) {
              storedKeyPair.public as DilithiumPublicKeyParameters
            } else {
              // Reconstruct from bytes
              DilithiumPublicKeyParameters(DilithiumParameters.dilithium3, publicKeyBytes)
            }
          } catch (e: Exception) {
            throw IllegalArgumentException("Failed to parse Dilithium public key: ${e.message}")
          }
          
          val verifier = DilithiumSigner()
          verifier.init(false, publicKey)
          val isValid = verifier.verifySignature(messageBytes, signatureBytes)
          
          Log.d(TAG, "Dilithium verification completed")
          Log.d(TAG, "Verification result: $isValid")
          
          promise.resolve(isValid)
        } catch (e: IllegalArgumentException) {
          Log.e(TAG, "Invalid input for Dilithium verification", e)
          promise.reject("DILITHIUM_VERIFY_ERROR", "Invalid input: ${e.message}", e)
        } catch (e: Exception) {
          Log.e(TAG, "Dilithium verification failed", e)
          promise.reject("DILITHIUM_VERIFY_ERROR", "Failed to verify Dilithium signature: ${e.message}", e)
        }
      }
    }
  }
}