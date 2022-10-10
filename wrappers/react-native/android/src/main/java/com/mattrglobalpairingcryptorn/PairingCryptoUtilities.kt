package com.mattrglobalpairingcryptorn

import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableNativeArray
import com.facebook.react.bridge.WritableNativeMap

fun ByteArray.toReadableArray(): ReadableArray {
  val result = WritableNativeArray()

  forEach {
    result.pushInt(it.toInt());
  }

  return result;
}

fun ReadableArray.toByteArray(): ByteArray {
  val result = ByteArray(this.size());
  for (i in 0 until this.size() step 1) {
    result[i] = this.getInt(i).toByte()
  }
  return result;
}

fun ReadableMap.getByteArray(key: String): ByteArray {
  return (this.getArray(key) as ReadableArray).toByteArray();
}

fun ReadableMap.getArrayOfByteArrays(key: String): Array<ByteArray>? {
  val array = this.getArray(key) ?: return null;
  val result = Array(array.size(), init = { ByteArray(0) })

  for (i in 0 until array.size() step 1) {
    val subArray = array.getArray(i)
    if (subArray != null) {
      result[i] = subArray.toByteArray()
    }
  }

  return result;
}

fun WritableNativeMap.putByteArray(key: String, byteArray: ByteArray) {
  val array = byteArray.toReadableArray();
  this.putArray(key, array);
}
