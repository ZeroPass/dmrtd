//  Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.

import 'dart:typed_data';
import '../lds/asn1ObjectIdentifiers.dart';

abstract class AccessKey{
  // described in ICAO 9303 p11 - 4.4.4.1 MSE:Set AT - Reference of a public key / secret key
  abstract int PACE_REF_KEY_TAG; //MRZ or CAN tag;


  Uint8List Kpi(CipherAlgorithm cipherAlgorithm, KEY_LENGTH keyLength);

  /// Very sensitive data. Do not use in production!
  @override
  String toString();
}