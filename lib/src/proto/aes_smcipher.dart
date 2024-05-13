// Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.


import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';
import 'package:logging/logging.dart';
import 'ssc.dart';
import 'iso7816/smcipher.dart';
import '../crypto/aes.dart';

class AES_SMCipher implements SMCipher {
  static final _log = Logger("AES_SMCipher");
  @override
  CipherAlgorithm type = CipherAlgorithm.AES;

  Uint8List KSenc;
  Uint8List KSmac;
  AESCipher cipher;

  AES_SMCipher(this.KSenc, this.KSmac, {required KEY_LENGTH size}):
        cipher = AESCipher(size: size);

  @override
  CipherAlgorithm get cipherAlgorithm => type;

  @override
  Uint8List encrypt(Uint8List data, {SSC? ssc}) {
    _log.debug ("encrypt: data size: ${data.length}, ssc: ${ssc?.toBytes().hex()}");
    _log.sdVerbose("encrypt: data: ${data.hex()}, KSenc: ${KSenc.hex()}");
    if (ssc == null)
      throw Exception("PACE_SMCipher_AES.encrypt: SSC should not be null");

    //IV = E(KSenc, SCC)
    _log.sdDebug("Encrypting IV with KSenc: ${KSenc.hex()}, ssc: ${ssc.toBytes().hex()}");
    Uint8List iv = cipher.encrypt(data: ssc.toBytes(), key: KSenc, mode: BLOCK_CIPHER_MODE.ECB);

    _log.sdVerbose("Encrypted IV: ${iv.hex()}");

    _log.sdDebug("Encrypting data with KSenc: ${KSenc.hex()}, iv: ${iv.hex()}");
    Uint8List encrypted = cipher.encrypt(data: data, key: KSenc,  iv: iv);

    _log.sdVerbose("Encrypted data: ${encrypted.hex()}");
    return encrypted;
  }

  @override
  Uint8List decrypt(Uint8List data, {SSC? ssc}) {
    _log.debug ("decrypt: data size: ${data.length}, ssc: ${ssc?.toBytes().hex()}");
    _log.sdVerbose("decrypt: data: ${data}, KSenc: ${KSenc.hex()}");
    if (ssc == null)
      throw Exception("PACE_SMCipher_AES.decrypt: SSC should not be null");

    //IV = E(KSenc, SCC)
    Uint8List iv = cipher.encrypt(data: ssc.toBytes(), key: KSenc, mode: BLOCK_CIPHER_MODE.ECB);
    _log.sdVerbose("IV: ${iv.hex()}");
    Uint8List decrypted =  cipher.decrypt(data: data, key: KSenc, iv: iv);
    _log.sdVerbose("Decrypted data: ${decrypted.hex()}");
    return decrypted;
  }

  @override
  Uint8List mac(Uint8List data) {
    _log.debug ("mac: data size: ${data.length}");
    _log.sdVerbose("mac: data: ${data.hex()}, KSmac: ${KSmac.hex()}");
    Uint8List cmac =  cipher.calculateCMAC(data: data, key: KSmac);
    _log.sdVerbose("CMAC: ${cmac.hex()}");
    return cmac;
  }
}