// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';

import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/internal.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
    test('TLV encoding test', () {
      expect( () => TLV.encodeLength(0x10000000) ,  throwsException     ); // Too big
      expect( TLV.encodeLength(0x7f)             ,  "7F".parseHex()     );
      expect( TLV.encodeLength(0x80)             ,  "8180".parseHex()   );
      expect( TLV.encodeLength(1999)             ,  "8207CF".parseHex() );

      // test vectors from ICAO 9303 p10 Section 3.9.6
      // ref: https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf
      expect( TLV.encodeIntValue(0x54, 0x0001) , "540101".parseHex()   );
      expect( TLV.encodeIntValue(0x54, 0xFFFF) , "5402FFFF".parseHex() );

      // test vectors from ICAO 9303 p11 Appendix D.4 to the Part 11
      // ref: https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
      expect( TLV.encode(0x87, "016375432908C044F6".parseHex()) , "8709016375432908C044F6".parseHex() );
      expect( TLV.encode(0x8E, "BF8B92D635FF24F8".parseHex())   , "8E08BF8B92D635FF24F8".parseHex()   );
      expect( TLV.encode(0x8E, "ED6705417E96BA55".parseHex())   , "8E08ED6705417E96BA55".parseHex()   );
      expect( TLV.encode(0x8E, "2EA28A70F3C7B535".parseHex())   , "8E082EA28A70F3C7B535".parseHex()   );
      expect( TLV.encodeIntValue(0x97, 0x04)                    , "970104".parseHex()                 );
      expect( TLV.encodeIntValue(0x97, 0x12)                    , "970112".parseHex()                 );

      // Fuzz testing
      expect( () => TLV.encodeLength(-1) , throwsTLVError(message: "Can't encode negative or greater than 16 777 215 length"));
      expect( () => TLV.encodeLength(0x10000000) , throwsTLVError(message: "Can't encode negative or greater than 16 777 215 length"));
    });

    test('TLV decoding test', () {
      expect( TLV.decodeLength("00".parseHex()).value           ,  0x00            );
      expect( TLV.decodeLength("0f".parseHex()).value           ,  0x0f            );
      expect( TLV.decodeLength("10".parseHex()).value           ,  0x10            );
      expect( TLV.decodeLength("7f".parseHex()).value           ,  0x7f            );
      expect( TLV.decodeLength("8180".parseHex()).value         ,  0x80            );
      expect( TLV.decodeLength("828000".parseHex()).value       ,  0x8000          );
      expect( TLV.decodeLength("83800000".parseHex()).value     ,  0x800000        );

      DecodedTV tv = TLV.decode("0000".parseHex());
      expect( tv.tag.value      , 0   );
      expect( tv.tag.encodedLen , 1   );
      expect( tv.encodedLen     , 2   );
      expect( tv.value.isEmpty , true );

      tv = TLV.decode("0100".parseHex());
      expect( tv.tag.value      , 1   );
      expect( tv.tag.encodedLen , 1   );
      expect( tv.encodedLen     , 2   );
      expect( tv.value.isEmpty , true );

      tv = TLV.decode("1000".parseHex());
      expect( tv.tag.value      , 0x10 );
      expect( tv.tag.encodedLen , 1    );
      expect( tv.encodedLen     , 2    );
      expect( tv.value.isEmpty  , true );

      tv = TLV.decode("1100".parseHex());
      expect( tv.tag.value      , 0x11 );
      expect( tv.tag.encodedLen , 1    );
      expect( tv.encodedLen     , 2    );
      expect( tv.value.isEmpty  , true );

      tv = TLV.decode("110100".parseHex());
      expect( tv.tag.value      , 0x11            );
      expect( tv.tag.encodedLen , 1               );
      expect( tv.encodedLen     , 3               );
      expect( tv.value.isEmpty  , false           );
      expect( tv.value          , "00".parseHex() );

      tv = TLV.decode("110101".parseHex());
      expect( tv.tag.value      , 0x11            );
      expect( tv.tag.encodedLen , 1               );
      expect( tv.encodedLen     , 3               );
      expect( tv.value.isEmpty  , false           );
      expect( tv.value          , "01".parseHex() );

      tv = TLV.decode("11010F".parseHex());
      expect( tv.tag.value      , 0x11            );
      expect( tv.tag.encodedLen , 1               );
      expect( tv.encodedLen     , 3               );
      expect( tv.value.isEmpty  , false           );
      expect( tv.value          , "0F".parseHex() );

      tv = TLV.decode("1101FF".parseHex());
      expect( tv.tag.value      , 0x11            );
      expect( tv.tag.encodedLen , 1               );
      expect( tv.encodedLen     , 3               );
      expect( tv.value.isEmpty  , false           );
      expect( tv.value          , "FF".parseHex() );

      // test vectors from ICAO 9303 p11 Appendix D.4 to the Part 11
      // ref: https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf

      // Case 1 Select COM
      var tvRAPDU = ResponseAPDU.fromBytes("990290008E08FA855A5D4C50A8ED9000".parseHex());
      var do99    = TLV.decode(tvRAPDU.data!);
      var do8E    = TLV.decode(tvRAPDU.data!.sublist(do99.encodedLen));
      expect( do99.encodedLen + do8E.encodedLen , tvRAPDU.data!.length );
      expect( do99.tag.value , 0x99 );
      expect( do99.value     , "9000".parseHex() );
      expect( do8E.tag.value , 0x8E );
      expect( do8E.value     , "FA855A5D4C50A8ED".parseHex() );

      // Case 2 Read Binary first 4 bytes
      tvRAPDU     = ResponseAPDU.fromBytes("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000".parseHex());
      var do87    = TLV.decode(tvRAPDU.data!);
      var decDO87 = TLV.decodeTagAndLength("60145F01".parseHex()); // decrypted data of DO87
      do99        = TLV.decode(tvRAPDU.data!.sublist(do87.encodedLen));
      do8E        = TLV.decode(tvRAPDU.data!.sublist(do87.encodedLen + do99.encodedLen));
      expect( do87.encodedLen + do99.encodedLen + do8E.encodedLen , tvRAPDU.data!.length );
      expect( do87.tag.value        , 0x87 );
      expect( do87.value            , "019FF0EC34F9922651".parseHex() );
      expect( decDO87.tag.value     , 0x60 );
      expect( decDO87.length.value  , 0x14 );
      expect( do99.tag.value        , 0x99 );
      expect( do99.value            , "9000".parseHex() );
      expect( do8E.tag.value        , 0x8E );
      expect( do8E.value            , "AD55CC17140B2DED".parseHex() );

      // Case 3 Read Binary the rest of the data
      tvRAPDU = ResponseAPDU.fromBytes("871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000".parseHex());
      do87    = TLV.decode(tvRAPDU.data!);
      do99    = TLV.decode(tvRAPDU.data!.sublist(do87.encodedLen));
      do8E    = TLV.decode(tvRAPDU.data!.sublist(do87.encodedLen + do99.encodedLen));
      expect( do87.encodedLen + do99.encodedLen + do8E.encodedLen , tvRAPDU.data!.length );
      expect( do87.tag.value        , 0x87 );
      expect( do87.value            , "01FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A".parseHex() );
      expect( do99.tag.value        , 0x99 );
      expect( do99.value            , "9000".parseHex() );
      expect( do8E.tag.value        , 0x8E );
      expect( do8E.value            , "C8B2787EAEA07D74".parseHex() );

      // Fuzz testing
      expect( () => TLV.decode(Uint8List(0))      , throwsTLVError(message: "Can't decode empty encodedTag")    );
      expect( () => TLV.decode("00".parseHex())   , throwsTLVError(message: "Can't decode empty encodedLength") );
      expect( () => TLV.decode("1F".parseHex())   , throwsTLVError(message: "Invalid encoded tag")              );
      expect( () => TLV.decode("1F80".parseHex()) , throwsTLVError(message: "Invalid encoded tag")              );

      expect( () => TLV.decodeLength("".parseHex())           , throwsTLVError(message: "Can't decode empty encodedLength") ); // No byte data
      expect( () => TLV.decodeLength("82".parseHex())         , throwsTLVError(message: "Invalid encoded length")           ); // Missing 2 bytes
      expect( () => TLV.decodeLength("8410000000".parseHex()) , throwsTLVError(message: "Encoded length is too big")        ); // Encoded length too big
      expect( () => TLV.decode("0082".parseHex())             , throwsTLVError(message: "Invalid encoded length")           ); // Missing 2 bytes
      expect( () => TLV.decode("008410000000".parseHex())     , throwsTLVError(message: "Encoded length is too big")        ); // Encoded length too big
      expect( () => TLV.decode("0001".parseHex())             , throwsRangeError                                            );
    });
}