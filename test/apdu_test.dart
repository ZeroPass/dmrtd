// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
@Tags(['iso7816'])
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/crypto/crypto_utils.dart';
import 'package:dmrtd/src/proto/iso7816/command_apdu.dart';
import 'package:dmrtd/src/proto/iso7816/response_apdu.dart';

void _testStatusWord(StatusWord sw, {required int sw1, required int sw2, required bool isSuccess, required bool isWarning, required bool isError, required String description})
{
  int swint = (sw1 << 8) + sw2;
  String swstr = swint.hex();
  expect( sw.sw1          , sw1                            );
  expect( sw.sw2          , sw2                            );
  expect( sw.value        , swint                          );
  expect( sw.hashCode     , swint                          );
  expect( sw              , StatusWord(sw1: sw1, sw2: sw2) );
  expect( sw.toBytes()    , swstr.parseHex()               );
  expect( sw.isSuccess()  , isSuccess                      );
  expect( sw.isWarning()  , isWarning                      );
  expect( sw.isError()    , isError                        );
  expect( sw.toString()   , 'sw=$swstr'                    );
  expect( sw.description(), description                    );

  expect( StatusWord.fromBytes(swstr.parseHex())               , sw );
  expect( StatusWord.fromBytes(('00$swstr').parseHex(), 1)     , sw );
  expect( StatusWord.fromBytes(('0F$swstr').parseHex(), 1)     , sw );
  expect( StatusWord.fromBytes(('10$swstr').parseHex(), 1)     , sw );
  expect( StatusWord.fromBytes(('FF$swstr').parseHex(), 1)     , sw );
  expect( StatusWord.fromBytes(('0000$swstr').parseHex(), 2)   , sw );
  expect( StatusWord.fromBytes(('0001$swstr').parseHex(), 2)   , sw );
  expect( StatusWord.fromBytes(('0010$swstr').parseHex(), 2)   , sw );
  expect( StatusWord.fromBytes(('000F$swstr').parseHex(), 2)   , sw );
  expect( StatusWord.fromBytes(('00F0$swstr').parseHex(), 2)   , sw );
  expect( StatusWord.fromBytes(('00FF$swstr').parseHex(), 2)   , sw );
  expect( StatusWord.fromBytes(('0000$swstr').parseHex(), 2)   , sw );
  expect( StatusWord.fromBytes(('0100$swstr').parseHex(), 2)   , sw );
  expect( StatusWord.fromBytes(('0101$swstr').parseHex(), 2)   , sw );
  expect( StatusWord.fromBytes(('0110$swstr').parseHex(), 2)   , sw );
  expect( StatusWord.fromBytes(('F000$swstr').parseHex(), 2)   , sw );
  expect( StatusWord.fromBytes(('F001$swstr').parseHex(), 2)   , sw );
  expect( StatusWord.fromBytes(('FEED$swstr').parseHex(), 2)   , sw );
  expect( StatusWord.fromBytes(('000000$swstr').parseHex(), 3) , sw );
  expect( StatusWord.fromBytes(('000001$swstr').parseHex(), 3) , sw );
  expect( StatusWord.fromBytes(('000010$swstr').parseHex(), 3) , sw );
  expect( StatusWord.fromBytes(('000100$swstr').parseHex(), 3) , sw );
  expect( StatusWord.fromBytes(('001000$swstr').parseHex(), 3) , sw );
  expect( StatusWord.fromBytes(('010000$swstr').parseHex(), 3) , sw );
  expect( StatusWord.fromBytes(('100000$swstr').parseHex(), 3) , sw );
  expect( StatusWord.fromBytes(('BEEDEE$swstr').parseHex(), 3) , sw );

  var random = Random.secure();
  var length = random.nextInt(1024);
  var randomBytes = List<int>.generate(length, (i) => random.nextInt(256));
  randomBytes += swstr.parseHex();
  expect( StatusWord.fromBytes(Uint8List.fromList(randomBytes), length) , sw );
}

void main() {
  test('Command APDU test', () {
    // Test case 1 - no data
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30).toBytes()                        , "00102030".parseHex()       );
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: null).toBytes()            , "00102030".parseHex()       );
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, ne: 0xA0).toBytes()              , "00102030A0".parseHex()     );
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, ne: 256).toBytes()               , "0010203000".parseHex()     );  //ne: 256 should be serialized as 0x00
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: null, ne: 256).toBytes()   , "0010203000".parseHex()     );  //ne: 256 should be serialized as 0x00
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, ne: 0xAABB).toBytes()            , "0010203000AABB".parseHex() );
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, ne: 65536).toBytes()             , "00102030000000".parseHex() );  //ne: 65536 should be serialized as 0x00 0x00
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: null, ne: 65536).toBytes() , "00102030000000".parseHex() );  //ne: 65536 should be serialized as 0x00 0x00

    // Tets case 2
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: "0102030405060708".parseHex()).toBytes()              , "00102030080102030405060708".parseHex()         );
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: "0102030405060708".parseHex(), ne: 0xA0).toBytes()    , "00102030080102030405060708A0".parseHex()       );
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: "0102030405060708".parseHex(), ne: 256).toBytes()     , "0010203008010203040506070800".parseHex()       );  //ne: 256 should be serialized as 0x00
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: "0102030405060708".parseHex(), ne: 0x0180).toBytes()  , "0010203000000801020304050607080180".parseHex() );
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: "0102030405060708".parseHex(), ne: 65536).toBytes()   , "0010203000000801020304050607080000".parseHex() );  //ne: 65536 should be serialized as 0x00 0x00

    // Test case 4 - data size (extended Lc) over 255 bytes
    var data = randomBytes(256);
    var tv   = Uint8List.fromList("00102030000100".parseHex() + data);
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: data).toBytes() , tv );

    tv   = Uint8List.fromList("00102030000100".parseHex() + data + "00A0".parseHex()); // Due to extended Lc, Le is encoded as 2 bytes
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: data, ne: 0xA0).toBytes() , tv );

    tv   = Uint8List.fromList("00102030000100".parseHex() + data + "0000".parseHex()); // Due to extended Lc, Le is encoded as 2 bytes
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: data, ne: 256).toBytes() , tv );

    tv   = Uint8List.fromList("00102030000100".parseHex() + data + "0180".parseHex()); // Due to extended Lc, Le is encoded as 2 bytes
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: data, ne: 0x0180).toBytes(), tv );

    tv   = Uint8List.fromList("00102030000100".parseHex() + data + "0000".parseHex()); // Due to extended Lc, Le is encoded as 2 bytes
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: data, ne: 65536).toBytes() , tv );

    // Test case 5
    // Test vectors from https://www.openscdp.org/sse4e/isosecurechannel.html
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30).toBytes()                                         , "00102030".parseHex()                   ); // Case 1 Command APDU
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, ne: 0x80).toBytes()                               , "0010203080".parseHex()                 ); // Case 2s Command APDU
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, ne: 0x180).toBytes()                              , "00102030000180".parseHex()             ); // Case 2e Command APDU
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: "41424344".parseHex()).toBytes()            , "001020300441424344".parseHex()         ); // Case 3s Command APDU
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: "41424344".parseHex(), ne: 0x80).toBytes()  , "00102030044142434480".parseHex()       ); // Case 4s Command APDU
    expect( CommandAPDU(cla: 0x00, ins: 0x10, p1: 0x20, p2: 0x30, data: "41424344".parseHex(), ne: 0x180).toBytes() , "00102030000004414243440180".parseHex() ); // Case 4e Command APDU
  }, tags: ['iso7816']);

  test('StatusWord tests', () {
    // Success
    _testStatusWord( StatusWord.success, sw1: 0x90, sw2: 0x00, isSuccess: true, isWarning: false, isError: false, description: 'Success' );
    _testStatusWord( StatusWord.remainingAvailableResponseBytes(32), sw1: StatusWord.sw1SuccessWithRemainingBytes, sw2: 0x20, isSuccess: true, isWarning: false, isError: false, description: '32 byte(s) are still available' );

    // Warnings
    _testStatusWord( StatusWord.noInformationGiven      , sw1: 0x62, sw2: 0x00, isSuccess: false, isWarning: true, isError: false, description: 'No information given'                        );
    _testStatusWord( StatusWord.possibleCorruptedData   , sw1: 0x62, sw2: 0x81, isSuccess: false, isWarning: true, isError: false, description: 'Part of returned data my be corrupted'       );
    _testStatusWord( StatusWord.unexpectedEOF           , sw1: 0x62, sw2: 0x82, isSuccess: false, isWarning: true, isError: false, description: 'End of file reached before reading Le bytes' );
    _testStatusWord( StatusWord.selectedFileInvalidated , sw1: 0x62, sw2: 0x83, isSuccess: false, isWarning: true, isError: false, description: 'Selected file invalidated'                   );
    _testStatusWord( StatusWord.wrongFCIFormat          , sw1: 0x62, sw2: 0x84, isSuccess: false, isWarning: true, isError: false, description: 'FCI not formatted according to 5.1.5'        );

    // Errors
    _testStatusWord( StatusWord.wrongLength                      , sw1: 0x67, sw2: 0x00, isSuccess: false, isWarning: false, isError: true, description: 'Wrong length (e.g. wrong Le field)'        );
    _testStatusWord( StatusWord.claFunctionNotSupported          , sw1: 0x68, sw2: 0x00, isSuccess: false, isWarning: false, isError: true, description: 'Functions in CLA not support'              );
    _testStatusWord( StatusWord.logicalChannelNotSupported       , sw1: 0x68, sw2: 0x81, isSuccess: false, isWarning: false, isError: true, description: 'Logical channel not supported'             );
    _testStatusWord( StatusWord.secureMessagingNotSupported      , sw1: 0x68, sw2: 0x82, isSuccess: false, isWarning: false, isError: true, description: 'Secure messaging not supported'            );
    _testStatusWord( StatusWord.commandNotAllowed                , sw1: 0x69, sw2: 0x00, isSuccess: false, isWarning: false, isError: true, description: 'Command not allowed'                       );
    _testStatusWord( StatusWord.incompatibleFileStructureCommand , sw1: 0x69, sw2: 0x81, isSuccess: false, isWarning: false, isError: true, description: 'Command incompatible with file structure'  );
    _testStatusWord( StatusWord.securityStatusNotSatisfied       , sw1: 0x69, sw2: 0x82, isSuccess: false, isWarning: false, isError: true, description: 'Security status not satisfied'             );
    _testStatusWord( StatusWord.authenticationMethodBlocked      , sw1: 0x69, sw2: 0x83, isSuccess: false, isWarning: false, isError: true, description: 'Authentication method blocked'             );
    _testStatusWord( StatusWord.referencedDataInvalidated        , sw1: 0x69, sw2: 0x84, isSuccess: false, isWarning: false, isError: true, description: 'Referenced data invalidated'               );
    _testStatusWord( StatusWord.conditionsNotSatisfied           , sw1: 0x69, sw2: 0x85, isSuccess: false, isWarning: false, isError: true, description: 'Conditions of use not satisfied'           );
    _testStatusWord( StatusWord.commandNotAllowedNoEF            , sw1: 0x69, sw2: 0x86, isSuccess: false, isWarning: false, isError: true, description: 'Command not allowed (no current EF)'       );
    _testStatusWord( StatusWord.smDataMissing                    , sw1: 0x69, sw2: 0x87, isSuccess: false, isWarning: false, isError: true, description: 'Expected SM data objects missing'          );
    _testStatusWord( StatusWord.smDataInvalid                    , sw1: 0x69, sw2: 0x88, isSuccess: false, isWarning: false, isError: true, description: 'SM data objects incorrect'                 );
    _testStatusWord( StatusWord.wrongParameters                  , sw1: 0x6A, sw2: 0x00, isSuccess: false, isWarning: false, isError: true, description: 'Wrong parameter(s) P1-P2'                  );
    _testStatusWord( StatusWord.invalidDataFieldParameters       , sw1: 0x6A, sw2: 0x80, isSuccess: false, isWarning: false, isError: true, description: 'Incorrect parameters in the data field'    );
    _testStatusWord( StatusWord.notSupported                     , sw1: 0x6A, sw2: 0x81, isSuccess: false, isWarning: false, isError: true, description: 'Function not supported'                    );
    _testStatusWord( StatusWord.fileNotFound                     , sw1: 0x6A, sw2: 0x82, isSuccess: false, isWarning: false, isError: true, description: 'File not found'                            );
    _testStatusWord( StatusWord.recordNotFound                   , sw1: 0x6A, sw2: 0x83, isSuccess: false, isWarning: false, isError: true, description: 'Record not found'                          );
    _testStatusWord( StatusWord.notEnoughSpaceInFile             , sw1: 0x6A, sw2: 0x84, isSuccess: false, isWarning: false, isError: true, description: 'Not enough memory space in the file'       );
    _testStatusWord( StatusWord.lcInconsistentWithTLV            , sw1: 0x6A, sw2: 0x85, isSuccess: false, isWarning: false, isError: true, description: 'Lc inconsistent with TLV structure'        );
    _testStatusWord( StatusWord.incorrectParameters              , sw1: 0x6A, sw2: 0x86, isSuccess: false, isWarning: false, isError: true, description: 'Incorrect parameters P1-P2'                );
    _testStatusWord( StatusWord.lcInconsistentWithParameters     , sw1: 0x6A, sw2: 0x87, isSuccess: false, isWarning: false, isError: true, description: 'Lc inconsistent with P1-P2'                );
    _testStatusWord( StatusWord.referencedDataNotFound           , sw1: 0x6A, sw2: 0x88, isSuccess: false, isWarning: false, isError: true, description: 'Referenced data not found'                 );
    _testStatusWord( StatusWord.wrongParameters2                 , sw1: 0x6B, sw2: 0x00, isSuccess: false, isWarning: false, isError: true, description: 'Wrong parameter(s) P1-P2'                  );
    _testStatusWord( StatusWord.invalidInstructionCode           , sw1: 0x6D, sw2: 0x00, isSuccess: false, isWarning: false, isError: true, description: 'Instruction code not supported or invalid' );
    _testStatusWord( StatusWord.classNotSupported                , sw1: 0x6E, sw2: 0x00, isSuccess: false, isWarning: false, isError: true, description: 'Class not supported'                       );
    _testStatusWord( StatusWord.noPreciseDiagnostics             , sw1: 0x6F, sw2: 0x00, isSuccess: false, isWarning: false, isError: true, description: 'No precise diagnosis'                      );
    _testStatusWord( StatusWord.leWrongLength(32)                , sw1: StatusWord.sw1WrongLengthWithExactLength, sw2: 0x20, isSuccess: false, isWarning: false, isError: true, description: 'Wrong length (exact length: 32)' );

    var random = Random.secure();
    var rsw1 = 0x91 + random.nextInt(256) % 0x6E;
    var rsw2 = random.nextInt(256);
     _testStatusWord( StatusWord(sw1:rsw1, sw2: rsw2), sw1: rsw1, sw2: rsw2, isSuccess: false, isWarning: false, isError: true, description: 'sw=${((rsw1 << 8) + rsw2).hex()}' );

     // Fuzz tests
     expect( ()=> StatusWord(sw1: -1, sw2: 0), throwsAssertionError );
     expect( ()=> StatusWord(sw1: 256, sw2: 0), throwsAssertionError );
     expect( ()=> StatusWord(sw1: 0, sw2: -1), throwsAssertionError );
     expect( ()=> StatusWord(sw1: 0, sw2: 256), throwsAssertionError );
     expect( ()=> StatusWord(sw1: -1, sw2: 256), throwsAssertionError );
     expect( ()=> StatusWord(sw1: 256, sw2: -1), throwsAssertionError );
     expect( ()=> StatusWord(sw1: 256, sw2: 256), throwsAssertionError );
     expect( ()=> StatusWord.fromBytes(Uint8List(0)), throwsArgumentError );
     expect( ()=> StatusWord.fromBytes('00'.parseHex()), throwsArgumentError );
     expect( ()=> StatusWord.fromBytes('0000'.parseHex(), 1), throwsArgumentError );
  }, tags: ['iso7816']);

  test('Response APDU test', () {
    // Test vectors from ICAO 9303 p11 appendix D.4
    // Test 1
    var rapdu = ResponseAPDU.fromBytes("990290008E08FA855A5D4C50A8ED9000".parseHex());
    expect( rapdu.status.sw1 , 0x90 );
    expect( rapdu.status.sw2 , 0x00 );
    expect( rapdu.data       , "990290008E08FA855A5D4C50A8ED".parseHex() );

    // Test 2
    rapdu = ResponseAPDU.fromBytes("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000".parseHex());
    expect( rapdu.status.sw1 , 0x90 );
    expect( rapdu.status.sw2 , 0x00 );
    expect( rapdu.data       , "8709019FF0EC34F9922651990290008E08AD55CC17140B2DED".parseHex() );

    // Test 3
    rapdu = ResponseAPDU.fromBytes("871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000".parseHex());
    expect( rapdu.status.sw1 , 0x90 );
    expect( rapdu.status.sw2 , 0x00 );
    expect( rapdu.data       , "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D74".parseHex() );

    // Test response status word
    rapdu = ResponseAPDU.fromBytes("9000".parseHex());
    expect( rapdu.status.sw1 , 0x90 );
    expect( rapdu.status.sw2 , 0x00 );
    expect( rapdu.data       , null );

    rapdu = ResponseAPDU.fromBytes("6A80".parseHex());
    expect( rapdu.status.sw1 , 0x6A );
    expect( rapdu.status.sw2 , 0x80 );
    expect( rapdu.data       , null );

    rapdu = ResponseAPDU.fromBytes("6A88".parseHex());
    expect( rapdu.status.sw1 , 0x6A );
    expect( rapdu.status.sw2 , 0x88 );
    expect( rapdu.data       , null );

    rapdu = ResponseAPDU.fromBytes("6300".parseHex());
    expect( rapdu.status.sw1 , 0x63 );
    expect( rapdu.status.sw2 , 0x00 );
    expect( rapdu.data       , null );

    rapdu = ResponseAPDU.fromBytes(Uint8List(2));
    expect( rapdu.status.sw1 , 0x00 );
    expect( rapdu.status.sw2 , 0x00 );
    expect( rapdu.data       , null );

    rapdu = ResponseAPDU.fromBytes("FFFF".parseHex());
    expect( rapdu.status.sw1 , 0xFF );
    expect( rapdu.status.sw2 , 0xFF );
    expect( rapdu.data       , null );

    expect( () =>  ResponseAPDU.fromBytes(Uint8List(0)), throwsArgumentError );
    expect( () =>  ResponseAPDU.fromBytes(Uint8List(1)), throwsArgumentError );
  }, tags: ['iso7816']);
}