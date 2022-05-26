// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/utils.dart';
import 'package:test/test.dart';


void main() {
  test('Bit count test', () {
    expect( () => Utils.bitCount(-1)   ,  throwsArgumentError );
    expect( Utils.bitCount(0)          ,  0 );
    expect( Utils.bitCount(1)          ,  1 );
    expect( Utils.bitCount(2)          ,  2 );
    expect( Utils.bitCount(3)          ,  2 );
    expect( Utils.bitCount(4)          ,  3 );
    expect( Utils.bitCount(5)          ,  3 );
    expect( Utils.bitCount(6)          ,  3 );
    expect( Utils.bitCount(8)          ,  4 );
    expect( Utils.bitCount(9)          ,  4 );
    expect( Utils.bitCount(10)         ,  4 );
    expect( Utils.bitCount(11)         ,  4 );
    expect( Utils.bitCount(12)         ,  4 );
    expect( Utils.bitCount(13)         ,  4 );
    expect( Utils.bitCount(14)         ,  4 );
    expect( Utils.bitCount(15)         ,  4 );
    expect( Utils.bitCount(16)         ,  5 );
    expect( Utils.bitCount(127)        ,  7 );
    expect( Utils.bitCount(255)        ,  8 );
    expect( Utils.bitCount(256)        ,  9 );
    expect( Utils.bitCount(511)        ,  9 );
    expect( Utils.bitCount(512)        , 10 );
    expect( Utils.bitCount(1023)       , 10 );
    expect( Utils.bitCount(1024)       , 11 );
    expect( Utils.bitCount(2047)       , 11 );
    expect( Utils.bitCount(2048)       , 12 );
    expect( Utils.bitCount(4095)       , 12 );
    expect( Utils.bitCount(4096)       , 13 );
    expect( Utils.bitCount(8191)       , 13 );
    expect( Utils.bitCount(8192)       , 14 );
    expect( Utils.bitCount(16383)      , 14 );
    expect( Utils.bitCount(16384)      , 15 );
    expect( Utils.bitCount(0x7FFF)     , 15 );
    expect( Utils.bitCount(0x8000)     , 16 );
    expect( Utils.bitCount(0xFFFF)     , 16 );
    expect( Utils.bitCount(0x10000)    , 17 );
    expect( Utils.bitCount(0xFFFFFF)   , 24 );
    expect( Utils.bitCount(0x1000000)  , 25 );
    expect( Utils.bitCount(0x10000000) , 29 );
    expect( Utils.bitCount(0xFFFFFFFF) , 32 );
  });

  test('Byte count test', () {
    expect( () => Utils.byteCount(-1)   ,  throwsArgumentError );
    expect( Utils.byteCount(0)          ,  0 );
    expect( Utils.byteCount(1)          ,  1 );
    expect( Utils.byteCount(2)          ,  1 );
    expect( Utils.byteCount(3)          ,  1 );
    expect( Utils.byteCount(4)          ,  1 );
    expect( Utils.byteCount(5)          ,  1 );
    expect( Utils.byteCount(6)          ,  1 );
    expect( Utils.byteCount(8)          ,  1 );
    expect( Utils.byteCount(9)          ,  1 );
    expect( Utils.byteCount(10)         ,  1 );
    expect( Utils.byteCount(11)         ,  1 );
    expect( Utils.byteCount(12)         ,  1 );
    expect( Utils.byteCount(13)         ,  1 );
    expect( Utils.byteCount(14)         ,  1 );
    expect( Utils.byteCount(15)         ,  1 );
    expect( Utils.byteCount(16)         ,  1 );
    expect( Utils.byteCount(127)        ,  1 );
    expect( Utils.byteCount(255)        ,  1 );
    expect( Utils.byteCount(256)        ,  2 );
    expect( Utils.byteCount(511)        ,  2 );
    expect( Utils.byteCount(512)        ,  2 );
    expect( Utils.byteCount(1023)       ,  2 );
    expect( Utils.byteCount(1024)       ,  2 );
    expect( Utils.byteCount(2047)       ,  2 );
    expect( Utils.byteCount(2048)       ,  2 );
    expect( Utils.byteCount(4095)       ,  2 );
    expect( Utils.byteCount(4096)       ,  2 );
    expect( Utils.byteCount(8191)       ,  2 );
    expect( Utils.byteCount(8192)       ,  2 );
    expect( Utils.byteCount(16383)      ,  2 );
    expect( Utils.byteCount(16384)      ,  2 );
    expect( Utils.byteCount(0x7FFF)     ,  2 );
    expect( Utils.byteCount(0x8000)     ,  2 );
    expect( Utils.byteCount(0xFFFF)     ,  2 );
    expect( Utils.byteCount(0x10000)    ,  3 );
    expect( Utils.byteCount(0xFFFFFF)   ,  3 );
    expect( Utils.byteCount(0x1000000)  ,  4 );
    expect( Utils.byteCount(0x10000000) ,  4 );
    expect( Utils.byteCount(0xFFFFFFFF) ,  4 );
  });

  test('Int to bytes test', () {
    expect( Utils.intToBin(0x0001)             , "01".parseHex()         );
    expect( Utils.intToBin(0xFFFF)             , "FFFF".parseHex()       );
    expect( Utils.intToBin(0x10101)            , "010101".parseHex()     );
    expect( Utils.intToBin(0x10000)            , "010000".parseHex()     );
    expect( Utils.intToBin(0x0001,  minLen: 2) , "0001".parseHex()       );
    expect( Utils.intToBin(0xFFFF,  minLen: 3) , "00FFFF".parseHex()     );
    expect( Utils.intToBin(0x10101, minLen: 4) , "00010101".parseHex()   );
    expect( Utils.intToBin(0x10000, minLen: 5) , "0000010000".parseHex() );
  });
}