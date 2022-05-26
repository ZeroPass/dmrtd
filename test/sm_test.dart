// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/proto/bac_smcipher.dart';
import 'package:test/test.dart';

import 'dart:typed_data';

import 'package:dmrtd/src/lds/tlv.dart';
import 'package:dmrtd/src/proto/mrtd_sm.dart';
import 'package:dmrtd/src/proto/iso7816/smcipher.dart';
import 'package:dmrtd/src/proto/iso7816/command_apdu.dart';
import 'package:dmrtd/src/proto/iso7816/response_apdu.dart';
import 'package:dmrtd/src/proto/iso7816/sm.dart';
import 'package:dmrtd/src/proto/ssc.dart';


void testProtecting(final CommandAPDU cmd, final SMCipher cipher, final SSC ssc, final Uint8List tvMaskedHeader, final Uint8List? tvDataDO, final Uint8List tvDO97, final Uint8List tvM, final Uint8List tvN, final Uint8List tvCC, final Uint8List tvDO8E, final Uint8List tvRawProtectedCmd) {
  final sscCpy = SSC(ssc.toBytes(), ssc.bitSize);
  final sm = MrtdSM(cipher, ssc);

  final pcmd = sm.maskCmd(cmd);
  expect( pcmd.rawHeader(), tvMaskedHeader );

  final dataDO = sm.generateDataDO(cmd);
  expect( dataDO, tvDataDO );

  final do97 = SecureMessaging.do97(pcmd.ne);
  expect( do97, tvDO97 );

  final M = sm.generateM(cmd: pcmd, dataDO: dataDO, do97: do97);
  expect( M, tvM );

  final N = sm.generateN(M: M);
  expect( N, tvN );

  // ignore: non_constant_identifier_names
  final CC = cipher.mac(N);
  expect( CC, tvCC );

  final do8E = SecureMessaging.do8E(CC);
  expect( do8E, tvDO8E );

  sm.ssc = sscCpy;
  expect( sm.protect(cmd).toBytes(), tvRawProtectedCmd );
}

void testUprotecting(final ResponseAPDU rapdu, final SMCipher cipher, final SSC ssc, final Uint8List? tvDataDO, final Uint8List tvDO99, final Uint8List tvDO8E, final Uint8List tvK, final Uint8List tvCC, final Uint8List? tvDecryptedData, final Uint8List tvRawUnprotectedRAPDU) {
  if(rapdu.status != StatusWord.success) {
    return;
  }

  final sscCpy = SSC(ssc.toBytes(), ssc.bitSize);
  final sm = MrtdSM(cipher, ssc);

  final dataDO  = sm.parseDataDOFromRAPDU(rapdu);
  expect( dataDO != null ? TLV.encode(dataDO.tag.value, dataDO.value) : null, tvDataDO );

  final do99 = sm.parseDO99FromRAPDU(rapdu, (dataDO?.encodedLen ?? 0));
  expect( TLV.encode(do99.tag.value, do99.value), tvDO99 );
  expect( StatusWord.fromBytes(do99.value), rapdu.status );

  final do8EStart = (dataDO?.encodedLen ?? 0) + do99.encodedLen;
  final do8E      = sm.parseDO8EFromRAPDU(rapdu, do8EStart);
  expect( TLV.encode(do8E.tag.value, do8E.value) , tvDO8E );

  final K = sm.generateK(data: rapdu.data!.sublist(0, do8EStart));
  expect( K , tvK );

  // ignore: non_constant_identifier_names
  final CC = cipher.mac(K);
  expect( CC , tvCC );

  final data = sm.decryptDataDO(dataDO);
  expect( data , tvDecryptedData );

  sm.ssc = sscCpy;
  expect( sm.unprotect(rapdu).toBytes(), tvRawUnprotectedRAPDU );
}

void main() {
  test('Testing MRTD Secure Messaging', () {

    // Test vectors taken from Appendix D.4 to the Part 11 of ICAO 7816 p11 doc
    final tvKSEnc  = "979EC13B1CBFE9DCD01AB0FED307EAE5".parseHex();
    final tvKSMAC  = "F1CB1F1FB5ADF208806B89DC579DC1F8".parseHex();
    final smCipher = BAC_SMCipher(tvKSEnc, tvKSMAC);
    final tvSSC    = DESedeSSC("887022120C06C226".parseHex());

    // Test case 1
    var tvCmdAPDU        = CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x02, p2: 0x0C, data: "011E".parseHex());
    var tvMaskedHeader   = "0CA4020C".parseHex();
    Uint8List? tvDataDO  = "8709016375432908C044F6".parseHex();
    var tvDO97           = Uint8List(0);
    var tvM              = "0CA4020C800000008709016375432908C044F6".parseHex();
    var tvN              = "887022120C06C2270CA4020C800000008709016375432908C044F68000000000".parseHex();
    var tvCC             = "BF8B92D635FF24F8".parseHex();
    var tvDO8E           = "8E08BF8B92D635FF24F8".parseHex();
    var tvProtectedCmd   = "0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800".parseHex();

    testProtecting(
      tvCmdAPDU,
      smCipher,
      tvSSC,
      tvMaskedHeader,
      tvDataDO,
      tvDO97,
      tvM,
      tvN,
      tvCC,
      tvDO8E,
      tvProtectedCmd
    );

    var tvProtectedRAPDU       = ResponseAPDU.fromBytes("990290008E08FA855A5D4C50A8ED9000".parseHex());
    tvDataDO                   = null;
    var tvDO99                 = "99029000".parseHex();
    tvDO8E                     = "8E08FA855A5D4C50A8ED".parseHex();
    var tvK                    = "887022120C06C2289902900080000000".parseHex();
    tvCC                       = "FA855A5D4C50A8ED".parseHex();
    var tvRawUnprotectedRAPDU  = "9000".parseHex();
    Uint8List? tvDecryptedData;

    expect( tvSSC.toBytes() , "887022120C06C227".parseHex() );
    testUprotecting(
      tvProtectedRAPDU,
      smCipher,
      tvSSC,
      tvDataDO,
      tvDO99,
      tvDO8E,
      tvK,
      tvCC,
      tvDecryptedData,
      tvRawUnprotectedRAPDU
    );


    // Test case 2
    tvCmdAPDU        = CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, ne: 0x04);
    tvMaskedHeader   = "0CB00000".parseHex();
    tvDataDO         = Uint8List(0);
    tvDO97           = "970104".parseHex();
    tvM              = "0CB0000080000000970104".parseHex();
    tvN              = "887022120C06C2290CB00000800000009701048000000000".parseHex();
    tvCC             = "ED6705417E96BA55".parseHex();
    tvDO8E           = "8E08ED6705417E96BA55".parseHex();
    tvProtectedCmd   = "0CB000000D9701048E08ED6705417E96BA5500".parseHex();

    expect( tvSSC.toBytes() , "887022120C06C228".parseHex() );
    testProtecting(
      tvCmdAPDU,
      smCipher,
      tvSSC,
      tvMaskedHeader,
      tvDataDO,
      tvDO97,
      tvM,
      tvN,
      tvCC,
      tvDO8E,
      tvProtectedCmd
    );

    tvProtectedRAPDU       = ResponseAPDU.fromBytes("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000".parseHex());
    tvDataDO               = "8709019FF0EC34F9922651".parseHex();
    tvDO99                 = "99029000".parseHex();
    tvDO8E                 = "8E08AD55CC17140B2DED".parseHex();
    tvK                    = "887022120C06C22A8709019FF0EC34F99226519902900080".parseHex();
    tvCC                   = "AD55CC17140B2DED".parseHex();
    tvDecryptedData        = "60145F01".parseHex();
    tvRawUnprotectedRAPDU  = "60145F019000".parseHex();

    expect( tvSSC.toBytes() , "887022120C06C229".parseHex() );
    testUprotecting(
      tvProtectedRAPDU,
      smCipher,
      tvSSC,
      tvDataDO,
      tvDO99,
      tvDO8E,
      tvK,
      tvCC,
      tvDecryptedData,
      tvRawUnprotectedRAPDU
    );


    // Test case 3
    tvCmdAPDU        = CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x04, ne: 0x12);
    tvMaskedHeader   = "0CB00004".parseHex();
    tvDataDO         = Uint8List(0);
    tvDO97           = "970112".parseHex();
    tvM              = "0CB0000480000000970112".parseHex();
    tvN              = "887022120C06C22B0CB00004800000009701128000000000".parseHex();
    tvCC             = "2EA28A70F3C7B535".parseHex();
    tvDO8E           = "8E082EA28A70F3C7B535".parseHex();
    tvProtectedCmd   = "0CB000040D9701128E082EA28A70F3C7B53500".parseHex();

    expect( tvSSC.toBytes() , "887022120C06C22A".parseHex() );
    testProtecting(
      tvCmdAPDU,
      smCipher,
      tvSSC,
      tvMaskedHeader,
      tvDataDO,
      tvDO97,
      tvM,
      tvN,
      tvCC,
      tvDO8E,
      tvProtectedCmd
    );

    tvProtectedRAPDU       = ResponseAPDU.fromBytes("871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000".parseHex());
    tvDataDO               = "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A".parseHex();
    tvDO99                 = "99029000".parseHex();
    tvDO8E                 = "8E08C8B2787EAEA07D74".parseHex();
    tvK                    = "887022120C06C22C871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A9902900080".parseHex(); // Note test vector in specification is missing padding byte 0x80
    tvCC                   = "C8B2787EAEA07D74".parseHex();
    tvDecryptedData        = "04303130365F36063034303030305C026175".parseHex();
    tvRawUnprotectedRAPDU  = "04303130365F36063034303030305C0261759000".parseHex();

    expect( tvSSC.toBytes() , "887022120C06C22B".parseHex() );
    testUprotecting(
      tvProtectedRAPDU,
      smCipher,
      tvSSC,
      tvDataDO,
      tvDO99,
      tvDO8E,
      tvK,
      tvCC,
      tvDecryptedData,
      tvRawUnprotectedRAPDU
    );
  });
}