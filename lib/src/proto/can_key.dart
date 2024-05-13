//  Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.

import 'dart:typed_data';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';
import 'package:logging/logging.dart';
import 'package:dmrtd/extensions.dart';

import '../crypto/kdf.dart';
import 'access_key.dart';



class CanKeysError implements Exception {
  final String message;
  CanKeysError(this.message);
  @override
  String toString() => message;
}

/// Class defines Document Basic Access Keys as specified in section 9.7.2 of doc ICAO 9303 p11
/// which are used to establish secure messaging session via BAC protocol.
class CanKey extends AccessKey {
  static final _log = Logger("AccessKey.CanKeys");
  // described in ICAO 9303 p11 - 4.4.4.1 MSE:Set AT - Reference of a public key / secret key
  @override
  int PACE_REF_KEY_TAG = 0x02; //CAN

  late Uint8List _can;

  /// Constructs [CanKey] using passport CAN number [Uint8List].
  CanKey(String canNumber) {
    //docs https://www.icao.int/Meetings/TAG-MRTD/Documents/Tag-Mrtd-20/TagMrtd-20_WP020_en.pdf
    //3.1.6 CAN is 6 digits long
    final RegExp regex = RegExp(r'^\d{6}$');
    if (!regex.hasMatch(canNumber)) {
      throw CanKeysError("AccessKey.CanKeys; Code must be exactly 6 digits and only contain numbers");
    }

    Uint8List canNumberInList = Uint8List(6);
    for (int i = 0; i < 6; i++) {
      canNumberInList[i] = canNumber.codeUnitAt(i);
    }

    _can = canNumberInList;
  }


  /// Returns K-pi [kpi] to be used in PACE protocol.
  Uint8List Kpi (CipherAlgorithm cipherAlgorithm, KEY_LENGTH keyLength){
      if (cipherAlgorithm == CipherAlgorithm.DESede){
        //_cachedSeed = KDF(sha1, _can, Int32(3)).sublist(0, seedLen);
        return DeriveKey.desEDE(_can, paceMode: true);
      }
      else if (cipherAlgorithm == CipherAlgorithm.AES &&
               keyLength == KEY_LENGTH.s128) {
        return DeriveKey.aes128(_can, paceMode: true);
      }
      else if (cipherAlgorithm == CipherAlgorithm.AES &&
                keyLength == KEY_LENGTH.s192) {
        return DeriveKey.aes192(_can, paceMode: true);
      }
      else if (cipherAlgorithm == CipherAlgorithm.AES &&
                keyLength == KEY_LENGTH.s256) {
        return DeriveKey.aes256(_can, paceMode: true);
      }
      else {
        throw ArgumentError.value(cipherAlgorithm, null, "CanKeys; Unsupported cipher algorithm");
      }
  }

  /// Returns passport number used for calculating key seed.
  Uint8List get can => _can;

  @override
  String toString() {
    _log.warning("CanKeys.toString() called. This is very sensitive data. Do not use in production!");
    return "CanKeys; CAN: ${_can.hex()}";
    return super.toString();
  }

}