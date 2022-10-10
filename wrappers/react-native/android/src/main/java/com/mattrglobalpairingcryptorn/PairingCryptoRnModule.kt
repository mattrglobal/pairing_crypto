package com.mattrglobalpairingcryptorn

import pairing_crypto.Bls12381Sha256
import pairing_crypto.Bls12381Shake256
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.*

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
}
