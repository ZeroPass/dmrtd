//  Created by Nejc Skerjanc, copyright © 2024 ZeroPass. All rights reserved.

import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';
import 'package:test/test.dart';

import 'package:dmrtd/src/proto/access_key.dart';
import 'package:dmrtd/src/proto/dba_key.dart';
import 'package:dmrtd/src/proto/can_key.dart';


import 'package:dmrtd/src/extension/string_apis.dart';


void main() {
  test('DBA key testing (for BAC and PACE)', ()
  {
    //DBA can be used for BAC and PACE
    DBAKey dbaKeys = DBAKey(
        "T22000129", DateTime(1964, 8, 12), DateTime(2010, 10, 31),
        paceMode: true);

    final tvKeySeed = "7e2d2a41c74ea0b38cd36f863939bfa8e9032aad".parseHex();
    final tvKenc = "3dc4f8862f8a1570b57fefdcfec43e46".parseHex();
    final tvKmac = "bc641c6b2fa8b5704552322007761f85".parseHex();
    final tv_K_pi_for_PACE = "89ded1b26624ec1e634c1989302849dd".parseHex();

    // Derive Kenc and Kmac
    expect(dbaKeys.keySeed, tvKeySeed);
    expect(dbaKeys.encKey, tvKenc);
    expect(dbaKeys.macKey, tvKmac);
    expect(dbaKeys.Kpi(CipherAlgorithm.AES, KEY_LENGTH.s128), tv_K_pi_for_PACE);
  });

  test('CAN key testing', ()
  {
    CanKey canKey = CanKey("123456");
    final tv_K_pi_for_PACE = "591468cda83d65219cccb8560233600f".parseHex();
    expect(canKey.Kpi(CipherAlgorithm.AES, KEY_LENGTH.s128), tv_K_pi_for_PACE);
  });

}
