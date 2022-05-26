// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: constant_identifier_names

import 'package:crypto/crypto.dart';
import 'package:fixnum/fixnum.dart';
import 'dart:typed_data';


/// Implements key derivation function as specified in ICAO 9303 p11 Section 9.7.1
/// Key is derived by [hash] object using [keySeed] bytes and [counter] number.
// ignore: non_constant_identifier_names
Uint8List KDF(final Hash hash, final Uint8List keySeed, final Int32 counter) {
  Uint8List preimage = Uint8List(keySeed.length + 4);
  preimage.setRange(0, keySeed.length, keySeed);

  ByteData  piview = ByteData.view(preimage.buffer);
  piview.setInt32(keySeed.length, counter.toInt(), Endian.big);
  return hash.convert(preimage).bytes as Uint8List;
}


enum DeriveKeyType {
  // Encryption key types
   DESede,
   AES128,
   AES192,
   AES256,

   // MAC key types
   ISO9797MacAlg3,
   CMAC128,
   CMAC192,
   CMAC256
}

/// Implements key derivation function as specified in
/// ICAO 9303 p11 Sections: 9.7.1.1, 9.7.1.2, 9.7.1.3, 9.7.1.4
class DeriveKey {

  /// Returns key for ISO9797 MAC algorithm 3 derived from
  /// [keySeed] bytes and counter mode 2.
  static Uint8List iso9797MacAlg3(final Uint8List keySeed) {
    return derive(DeriveKeyType.ISO9797MacAlg3, keySeed);
  }

  /// Returns key for CMAC-128 derived from [keySeed] bytes and counter mode 2.
  static Uint8List cmac128(final Uint8List keySeed) {
    return derive(DeriveKeyType.CMAC128, keySeed);
  }

  /// Returns key for CMAC-192 derived from [keySeed] bytes and counter mode 2.
  static Uint8List cmac192(final Uint8List keySeed) {
    return derive(DeriveKeyType.CMAC192, keySeed);
  }

  /// Returns key for CMAC-256 derived from [keySeed] bytes and counter mode 2.
  static Uint8List cmac256(final Uint8List keySeed) {
    return derive(DeriveKeyType.CMAC256, keySeed);
  }

  /// Returns key for DESede derived from [keySeed] bytes and counter mode 1.
  /// If [paceMode] is true counter 3 is used.
  static Uint8List desEDE(final Uint8List keySeed, { final bool paceMode = false }) {
    return derive(DeriveKeyType.DESede, keySeed, paceMode: paceMode);
  }

  /// Returns key for AES-128 derived from [keySeed] bytes and counter mode 1.
  /// If [paceMode] is true counter 3 is used.
  static Uint8List aes128(final Uint8List keySeed, { final bool paceMode = false }) {
    return derive(DeriveKeyType.AES128, keySeed, paceMode: paceMode);
  }

  /// Returns key for AES-192 derived from [keySeed] bytes and counter mode 1.
  /// If [paceMode] is true counter 3 is used.
  static Uint8List aes192(final Uint8List keySeed, { final bool paceMode = false }) {
    return derive(DeriveKeyType.AES192, keySeed, paceMode: paceMode);
  }

  /// Returns key for AES-256 derived from [keySeed] bytes and counter mode 1.
  /// If [paceMode] is true counter 3 is used.
  static Uint8List aes256(final Uint8List keySeed, { final bool paceMode = false }) {
    return derive(DeriveKeyType.AES256, keySeed, paceMode: paceMode);
  }

  /// Returns key from [keySeed] bytes for specific [keyType] and
  /// counter mode specific for key type (1 - ENC mode, 2 - MAC mode).
  /// If [paceMode] is true counter 3 for encryption key types.
  static Uint8List derive(final DeriveKeyType keyType, final Uint8List keySeed, { final bool paceMode = false }) {
    Int32 mode =  Int32(paceMode ? 3 : 1); // PACE/ENC mode
    if(keyType == DeriveKeyType.ISO9797MacAlg3 ||
       keyType == DeriveKeyType.CMAC128        ||
       keyType == DeriveKeyType.CMAC192        ||
       keyType == DeriveKeyType.CMAC256) {
      mode = Int32(2); // MAC mode
    }

    switch(keyType) {
      case DeriveKeyType.DESede:
      case DeriveKeyType.ISO9797MacAlg3: {
        final key = KDF(sha1, keySeed, mode).sublist(0, 16); // use only 128 bits = 8 * 16;

        // Adjust even parity bits
        for (int i = 0; i < key.length; i++) {
          // count set bits
          var count = 0;
          for(int j = 0; j < 8; j++) {
            count += (key[i] >> j) & 0x01;
          }
          if(count % 2 == 0) { // if even bit count
            key[i] ^= 0x01;
          }
        }
        return key;
      }
      case DeriveKeyType.AES128:
      case DeriveKeyType.CMAC128: {
        return KDF(sha1, keySeed, mode).sublist(0, 16); // use only 128 bits = 8 * 16;
      }
      case DeriveKeyType.AES192:
      case DeriveKeyType.AES256:
      case DeriveKeyType.CMAC192:
      case DeriveKeyType.CMAC256: {
        var key = KDF(sha256, keySeed, mode);
        if(keyType == DeriveKeyType.AES192 ||
           keyType == DeriveKeyType.CMAC192) {
          key = key.sublist(0, 24); // use only 192 bits = 8 * 24;
        }
        return key;
      }
    }
  }
}