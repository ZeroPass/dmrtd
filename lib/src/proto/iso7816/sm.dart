// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import '../../lds/tlv.dart';
import '../../utils.dart';

import 'command_apdu.dart';
import 'response_apdu.dart';
import 'smcipher.dart';


class SMError implements Exception {
  final String message;
  SMError(this.message);
  @override
  String toString() => "SMError: $message";
}

// Class defines ISO/IEC 7816-4 Secure Messaging (SM) interface.
// ref: section 5.6 of ISO/IEC 7816-4 doc
abstract class SecureMessaging {
  static const tagDO85 = 0x85;
  static const tagDO87 = 0x87;
  static const tagDO8E = 0x8E;
  static const tagDO97 = 0x97;
  static const tagDO99 = 0x99;

  final SMCipher cipher;
  SecureMessaging(this.cipher);

  CommandAPDU protect(final CommandAPDU cmd);
  ResponseAPDU unprotect(final ResponseAPDU rapdu);

  static Uint8List do85(final Uint8List data) {
    return _buildDO(tagDO85, data);
  }

  static Uint8List do87(final Uint8List data, {bool dataIsPadded = true}) {
    if(data.isEmpty) {
      return Uint8List(0);
    }
    final data1 = Uint8List.fromList([dataIsPadded ? 0x01 : 0x02] + data); // Padding info byte defined in ISO/IEC 7816-4 part 5
    return _buildDO(tagDO87, data1);
  }

  static Uint8List do8E(final Uint8List data) {
    return _buildDO(tagDO8E, data);
  }

  static Uint8List do97(final int ne) {
    if(ne == 256 || ne == 65536) {
      return _buildDO(tagDO97, Uint8List(ne == 256 ? 1 : 2));
    }
    return _buildDO(tagDO97, Utils.intToBin(ne, minLen: 0));
  }

  static Uint8List do99(final int ne) {
    return _buildDO(tagDO99, Utils.intToBin(ne, minLen: 0));
  }

  static Uint8List _buildDO(final int tag, final Uint8List data) {
    assert(tag < 256);
    if(data.isEmpty) {
      return Uint8List(0);
    }
    return TLV.encode(tag, data);
  }
}