//  Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

import '../crypto/kdf.dart';
import '../lds/mrz.dart';
import '../extension/datetime_apis.dart';
import '../extension/string_apis.dart';


/// Class defines Document Basic Access Keys as specified in section 9.7.2 of doc ICAO 9303 p11
/// which are used to establish secure messaging session via BAC protocol.
class DBAKeys {
  late String _mrtdNum;
  late String _dob;
  late String _doe;
  Uint8List? _cachedSeed;

  /// Constructs [DBAKeys] using passport number [mrtdNumber],
  /// passport owner's [dateOfBirth] and passport [dateOfExpiry].
  DBAKeys(String mrtdNumber, DateTime dateOfBirth, DateTime dateOfExpiry) {
    _mrtdNum = mrtdNumber;
    _dob     = dateOfBirth.formatYYMMDD();
    _doe     = dateOfExpiry.formatYYMMDD();
  }

  /// Constructs [DBAKeys] from [mrz].
  factory DBAKeys.fromMRZ(MRZ mrz) {
    return DBAKeys(mrz.documentNumber, mrz.dateOfBirth, mrz.dateOfExpiry);
  }

  /// Returns encryption key [Kenc] to be used in BAC protocol.
  Uint8List get encKey {
    return DeriveKey.desEDE(keySeed);
  }

  /// Returns MAC key [Kmac] to be used in BAC protocol.
  Uint8List get macKey {
    return DeriveKey.iso9797MacAlg3(keySeed);
  }

  /// Returns Kseed as specified in Appendix D.2
  /// to the Part 11 of doc ICAO 9303 p11
  Uint8List get keySeed {
    if(_cachedSeed == null) {
      final paddedMrtdNum = _mrtdNum.padRight(9, '<');
      final cdn = MRZ.calculateCheckDigit(paddedMrtdNum);
      final cdb = MRZ.calculateCheckDigit(_dob);
      final cde = MRZ.calculateCheckDigit(_doe);

      final kmrz = "$paddedMrtdNum$cdn$_dob$cdb$_doe$cde";
      final hash = sha1.convert(kmrz.codeUnits);
      _cachedSeed = hash.bytes.sublist(0, 16) as Uint8List?;
    }
    return _cachedSeed!;
  }

  /// Returns passport number used for calculating key seed.
  String get mrtdNumber => _mrtdNum;

  /// Returns passport owner's date of birth used for calculating key seed.
  DateTime get dateOfBirth => _dob.parseDateYYMMDD();

  /// Returns passport date of expiry used for calculating key seed.
  DateTime get dateOfExpiry => _doe.parseDateYYMMDD();
}