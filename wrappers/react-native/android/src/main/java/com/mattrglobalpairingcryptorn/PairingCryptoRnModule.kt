package com.mattrglobalpairingcryptorn

import pairing_crypto.Bls12381Sha256
import pairing_crypto.Bls12381Shake256
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.*
import java.util.*

class PairingCryptoRnModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {

  override fun getName(): String {
    return "PairingCryptoRn"
  }

  @ReactMethod
  fun Bls12381Sha256GenerateKeyPair(request: ReadableMap, promise: Promise) {
    val result = WritableNativeMap()
    val ikm = ByteArray(32)
    val keyInfo = ByteArray(32)

    var cipherSuite = Bls12381Sha256()
    var keyPair = cipherSuite.generateKeyPair(ikm, keyInfo)

    result.putArray("publicKey", keyPair.publicKey.toReadableArray())
    result.putArray("secretKey", keyPair.secretKey.toReadableArray())
    promise.resolve(result as ReadableMap)
  }

  @ReactMethod
  fun Bls12381Shake256GenerateKeyPair(request: ReadableMap, promise: Promise) {
    val result = WritableNativeMap()
    val ikm = ByteArray(32)
    val keyInfo = ByteArray(32)

    var cipherSuite = Bls12381Shake256()
    var keyPair = cipherSuite.generateKeyPair(ikm, keyInfo)

    result.putArray("publicKey", keyPair.publicKey.toReadableArray())
    result.putArray("secretKey", keyPair.secretKey.toReadableArray())
    promise.resolve(result as ReadableMap)
  }

  @ReactMethod
  fun Bls12381Sha256Sign(request: ReadableMap, promise: Promise) {
    try {
      var secretKey: ByteArray? = null
      var publicKey: ByteArray? = null
      var header: ByteArray? = null
      var messages: Array<ByteArray>? = null

      if (request.hasKey("secretKey")) {
        secretKey = request.getByteArray("secretKey")
      }
      if (request.hasKey("publicKey")) {
        publicKey = request.getByteArray("publicKey")
      }
      if (request.hasKey("header")) {
        header = request.getByteArray("header")
      }
      if (request.hasKey("messages")) {
        messages = request.getArrayOfByteArrays("messages")
      }

      var cipherSuite = Bls12381Sha256()
      var signature = cipherSuite.sign(secretKey, publicKey, header, messages)

      promise.resolve(signature.toReadableArray())
    } catch (exception: Exception) {
      promise.reject(exception)
    }
  }

  @ReactMethod
  fun Bls12381Shake256Sign(request: ReadableMap, promise: Promise) {
    try {
      var secretKey: ByteArray? = null
      var publicKey: ByteArray? = null
      var header: ByteArray? = null
      var messages: Array<ByteArray>? = null

      if (request.hasKey("secretKey")) {
        secretKey = request.getByteArray("secretKey")
      }
      if (request.hasKey("publicKey")) {
        publicKey = request.getByteArray("publicKey")
      }
      if (request.hasKey("header")) {
        header = request.getByteArray("header")
      }
      if (request.hasKey("messages")) {
        messages = request.getArrayOfByteArrays("messages")
      }

      var cipherSuite = Bls12381Shake256()
      var signature = cipherSuite.sign(secretKey, publicKey, header, messages)

      promise.resolve(signature.toReadableArray())
    } catch (exception: Exception) {
      promise.reject(exception)
    }
  }

  @ReactMethod
  fun Bls12381Sha256Verify(request: ReadableMap, promise: Promise) {
    try {
      var publicKey: ByteArray? = null
      var header: ByteArray? = null
      var signature: ByteArray? = null
      var messages: Array<ByteArray>? = null

      if (request.hasKey("publicKey")) {
        publicKey = request.getByteArray("publicKey")
      }
      if (request.hasKey("header")) {
        header = request.getByteArray("header")
      }
      if (request.hasKey("signature")) {
        signature = request.getByteArray("signature")
      }
      if (request.hasKey("messages")) {
        messages = request.getArrayOfByteArrays("messages")
      }

      var cipherSuite = Bls12381Sha256()
      var verified = cipherSuite.verify(publicKey, header, signature, messages)

      promise.resolve(verified)
    } catch (exception: Exception) {
      promise.reject(exception)
    }
  }

  @ReactMethod
  fun Bls12381Shake256Verify(request: ReadableMap, promise: Promise) {
    try {
      var publicKey: ByteArray? = null
      var header: ByteArray? = null
      var signature: ByteArray? = null
      var messages: Array<ByteArray>? = null

      if (request.hasKey("publicKey")) {
        publicKey = request.getByteArray("publicKey")
      }
      if (request.hasKey("header")) {
        header = request.getByteArray("header")
      }
      if (request.hasKey("signature")) {
        signature = request.getByteArray("signature")
      }
      if (request.hasKey("messages")) {
        messages = request.getArrayOfByteArrays("messages")
      }

      var cipherSuite = Bls12381Shake256()
      var verified = cipherSuite.verify(publicKey, header, signature, messages)

      promise.resolve(verified)
    } catch (exception: Exception) {
      promise.reject(exception)
    }
  }

  @ReactMethod
  fun Bls12381Sha256ProofVerify(request: ReadableMap, promise: Promise) {
    try {
      var header: ByteArray? = null
      var presentationHeader: ByteArray? = null
      var publicKey: ByteArray? = null
      var proof: ByteArray? = null
      var messages: HashMap<Int, ByteArray>? = null

      if (request.hasKey("publicKey")) {
        publicKey = request.getByteArray("publicKey")
      }
      if (request.hasKey("header")) {
        header = request.getByteArray("header")
      }
      if (request.hasKey("presentationHeader")) {
        presentationHeader = request.getByteArray("presentationHeader")
      }
      if (request.hasKey("proof")) {
        proof = request.getByteArray("proof")
      }
      if (request.hasKey("messages")) {
        messages = request.getMapOfByteArrays("messages")
      }

      var cipherSuite = Bls12381Sha256()
      var verified = cipherSuite.verifyProof(publicKey, header, presentationHeader, proof, messages)

      promise.resolve(verified)
    } catch (exception: Exception) {
      promise.reject(exception)
    }
  }

  @ReactMethod
  fun Bls12381Shake256ProofVerify(request: ReadableMap, promise: Promise) {
    try {
      var header: ByteArray? = null
      var presentationHeader: ByteArray? = null
      var publicKey: ByteArray? = null
      var proof: ByteArray? = null
      var messages: HashMap<Int, ByteArray>? = null

      if (request.hasKey("publicKey")) {
        publicKey = request.getByteArray("publicKey")
      }
      if (request.hasKey("header")) {
        header = request.getByteArray("header")
      }
      if (request.hasKey("presentationHeader")) {
        presentationHeader = request.getByteArray("presentationHeader")
      }
      if (request.hasKey("proof")) {
        proof = request.getByteArray("proof")
      }
      if (request.hasKey("messages")) {
        messages = request.getMapOfByteArrays("messages")
      }

      var cipherSuite = Bls12381Shake256()
      var verified = cipherSuite.verifyProof(publicKey, header, presentationHeader, proof, messages)

      promise.resolve(verified)
    } catch (exception: Exception) {
      promise.reject(exception)
    }
  }

  @ReactMethod
  fun Bls12381Sha256ProofGen(request: ReadableMap, promise: Promise) {
    try {
      var header: ByteArray? = null
      var presentationHeader: ByteArray? = null
      var publicKey: ByteArray? = null
      var signature: ByteArray? = null
      var verifySignature: Boolean = false
      var disclosedIndices: HashSet<Int>? = null
      var messages: Array<ByteArray>? = null

      if (request.hasKey("publicKey")) {
        publicKey = request.getByteArray("publicKey")
      }
      if (request.hasKey("header")) {
        header = request.getByteArray("header")
      }
      if (request.hasKey("presentationHeader")) {
        presentationHeader = request.getByteArray("presentationHeader")
      }
      if (request.hasKey("signature")) {
        signature = request.getByteArray("signature")
      }
      if (request.hasKey("verifySignature")) {
        verifySignature = request.getBoolean("verifySignature")
      }
      if (request.hasKey("messages")) {
        val array = request.getArray("messages") as ReadableArray

        disclosedIndices = HashSet<Int>()
        messages = Array(array.size(), init = { ByteArray(0) })

        for (i in 0 until array.size() step 1) {
          val item = array.getMap(i)
          val reveal = item?.getBoolean("reveal") ?: false
          val messageBytes = item?.getByteArray("value")

          if (reveal) {
            disclosedIndices.add(i)
          }
          if (messageBytes != null) {
            messages[i] = messageBytes
          }
        }
      }

      var cipherSuite = Bls12381Sha256()
      var proof = cipherSuite.createProof(publicKey, header, presentationHeader, signature, verifySignature, disclosedIndices, messages)

      promise.resolve(proof.toReadableArray())
    } catch (exception: Exception) {
      promise.reject(exception)
    }
  }

  @ReactMethod
  fun Bls12381Shake256ProofGen(request: ReadableMap, promise: Promise) {
    try {
      var header: ByteArray? = null
      var presentationHeader: ByteArray? = null
      var publicKey: ByteArray? = null
      var signature: ByteArray? = null
      var verifySignature: Boolean = false
      var disclosedIndices: HashSet<Int>? = null
      var messages: Array<ByteArray>? = null

      if (request.hasKey("publicKey")) {
        publicKey = request.getByteArray("publicKey")
      }
      if (request.hasKey("header")) {
        header = request.getByteArray("header")
      }
      if (request.hasKey("presentationHeader")) {
        presentationHeader = request.getByteArray("presentationHeader")
      }
      if (request.hasKey("signature")) {
        signature = request.getByteArray("signature")
      }
      if (request.hasKey("verifySignature")) {
        verifySignature = request.getBoolean("verifySignature")
      }
      if (request.hasKey("messages")) {
        val array = request.getArray("messages") as ReadableArray

        disclosedIndices = HashSet<Int>()
        messages = Array(array.size(), init = { ByteArray(0) })

        for (i in 0 until array.size() step 1) {
          val item = array.getMap(i)
          val reveal = item?.getBoolean("reveal") ?: false
          val messageBytes = item?.getByteArray("value")

          if (reveal) {
            disclosedIndices.add(i)
          }
          if (messageBytes != null) {
            messages[i] = messageBytes
          }
        }
      }

      var cipherSuite = Bls12381Shake256()
      var proof = cipherSuite.createProof(publicKey, header, presentationHeader, signature, verifySignature, disclosedIndices, messages)

      promise.resolve(proof.toReadableArray())
    } catch (exception: Exception) {
      promise.reject(exception)
    }
  }
}
