//  Created by smlu, copyright © 2020 ZeroPass. All rights reserved.

import 'dart:typed_data';
import 'package:test/test.dart';

import 'package:dmrtd/src/crypto/crypto_utils.dart';
import 'package:dmrtd/src/proto/iso7816/command_apdu.dart';
import 'package:dmrtd/src/proto/iso7816/response_apdu.dart';
import 'package:dmrtd/src/extension/string_apis.dart';

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
  });

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

    expect( () =>  ResponseAPDU.fromBytes(null), throwsArgumentError );
    expect( () =>  ResponseAPDU.fromBytes(Uint8List(0)), throwsArgumentError );
    expect( () =>  ResponseAPDU.fromBytes(Uint8List(1)), throwsArgumentError );
  });
}