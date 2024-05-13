// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';

import 'iso7816/smcipher.dart';
import '../crypto/des.dart';
import '../crypto/iso9797.dart';
import './ssc.dart';

// ignore: camel_case_types
class DES_SMCipher implements SMCipher{
  @override
  CipherAlgorithm type = CipherAlgorithm.DESede;

  Uint8List encKey;
  Uint8List macKey;

  DES_SMCipher(this.encKey, this.macKey);

  @override
  CipherAlgorithm get cipherAlgorithm => type;

  @override
  Uint8List encrypt(Uint8List data, {SSC? ssc}) {
    return DESedeEncrypt(key: encKey, iv: Uint8List(DESedeCipher.blockSize), data: data, padData: false);
  }

  @override
  Uint8List decrypt(Uint8List edata, {SSC? ssc}) {
    return DESedeDecrypt(key: encKey, iv: Uint8List(DESedeCipher.blockSize), edata: edata, paddedData: false);
  }

  @override
  Uint8List mac(Uint8List data, {SSC? ssc}) {
    return ISO9797.macAlg3(macKey, data, padMsg: false);
  }
}