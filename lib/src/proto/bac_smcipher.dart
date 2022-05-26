// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'iso7816/smcipher.dart';
import '../crypto/des.dart';
import '../crypto/iso9797.dart';

// ignore: camel_case_types
class BAC_SMCipher implements SMCipher {
  Uint8List encKey;
  Uint8List macKey;

  BAC_SMCipher(this.encKey, this.macKey);

  @override
  Uint8List encrypt(Uint8List data) {
    return DESedeEncrypt(key: encKey, iv: Uint8List(DESedeCipher.blockSize), data: data, padData: false);
  }

  @override
  Uint8List decrypt(Uint8List edata) {
    return DESedeDecrypt(key: encKey, iv: Uint8List(DESedeCipher.blockSize), edata: edata, paddedData: false);
  }

  @override
  Uint8List mac(Uint8List data) {
    return ISO9797.macAlg3(macKey, data, padMsg: false);
  }
}