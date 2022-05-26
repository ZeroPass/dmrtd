//  Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: constant_identifier_names

import 'dart:typed_data';
import 'des.dart';

/// Class defines ISO/IEC 9797-1 MAC algorithm 3 and padding method 2.
class ISO9797 {
  static const int macAlg3_DigestLen = DESCipher.blockSize;
  static const int macAlg3_Key1Len   = 16; // First possible Alg3 MAC key len is 16 bytes.
  static const int macAlg3_Key2Len   = 24; // Second possible Alg3 MAC key len is 16 bytes.

  /// Function returns CMAC result according to ISO9797-1 Algorithm 3 scheme
  /// using DES encryption algorithm.
  ///
  /// The size of [key] should be 16 or 24 bytes.
  /// The [msg] if [padMsg] is set to false should be padded to the nearest multiple of 8.
  /// When [padMsg] is true, the [msg] is padded according to the ISO/IEC 9797-1, padding method 2.
  ///
  static macAlg3(Uint8List key, Uint8List msg, { bool padMsg = true }) {
    if(key.length != macAlg3_Key1Len && key.length != macAlg3_Key2Len) {
      throw ArgumentError.value(key, "key length must be 16 or 24");
    }

    final ka = key.sublist(0, 8);
    final kb = key.sublist(8, 16);
    final kc = key.length == macAlg3_Key1Len ? ka : key.sublist(16, 24);

    final cipher = DESCipher(key: ka, iv: Uint8List(DESCipher.blockSize));
    var mac = cipher.encrypt(msg, padData: padMsg);
    mac = mac.sublist(mac.length - DESCipher.blockSize);

    cipher.key = kb;
    mac = cipher.decryptBlock(mac);

    cipher.key = kc;
    mac = cipher.encryptBlock(mac);

    return mac;
  }

  // Returns padded data according to ISO/IEC 9797-1, padding method 2 scheme.
  static Uint8List pad(Uint8List data) {
    final Uint8List padBlock = Uint8List.fromList([0x80, 0, 0, 0, 0, 0, 0, 0]);
    final padSize = DESCipher.blockSize - (data.length % DESCipher.blockSize);
    return Uint8List.fromList(data + padBlock.sublist(0, padSize));
  }

  // Returns unpadded data according to ISO/IEC 9797-1, padding method 2 scheme.
  static Uint8List unpad(Uint8List data) {
    var i = data.length - 1;
      while (data[i] == 0x00) {
          i -= 1;
      }
      if(data[i] == 0x80) {
        return data.sublist(0, i);
      }
      return data;
  }
}