//  Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:test/test.dart';

import 'package:dmrtd/src/crypto/iso9797.dart';
import 'package:dmrtd/src/extension/string_apis.dart';


void main() {
  test('ISO9797 padding method 2', () {
    var tv       = "".parseHex();
    var tvPadded = "8000000000000000".parseHex();
    expect( ISO9797.pad(tv)        , tvPadded );
    expect( ISO9797.unpad(tvPadded), tv       );

    tv       = "0001020304050607".parseHex();
    tvPadded = "00010203040506078000000000000000".parseHex();
    expect( ISO9797.pad(tv)        , tvPadded );
    expect( ISO9797.unpad(tvPadded), tv       );

    tv       = "000102030405060708".parseHex();
    tvPadded = "00010203040506070880000000000000".parseHex();
    expect( ISO9797.pad(tv)        , tvPadded );
    expect( ISO9797.unpad(tvPadded), tv       );

    tv       = "00010203040506070809".parseHex();
    tvPadded = "00010203040506070809800000000000".parseHex();
    expect( ISO9797.pad(tv)        , tvPadded );
    expect( ISO9797.unpad(tvPadded), tv       );

    tv       = "000102030405060708090A".parseHex();
    tvPadded = "000102030405060708090A8000000000".parseHex();
    expect( ISO9797.pad(tv)        , tvPadded );
    expect( ISO9797.unpad(tvPadded), tv       );

    tv       = "000102030405060708090A0B".parseHex();
    tvPadded = "000102030405060708090A0B80000000".parseHex();
    expect( ISO9797.pad(tv)        , tvPadded );
    expect( ISO9797.unpad(tvPadded), tv       );

    tv       = "000102030405060708090A0B0C".parseHex();
    tvPadded = "000102030405060708090A0B0C800000".parseHex();
    expect( ISO9797.pad(tv)        , tvPadded );
    expect( ISO9797.unpad(tvPadded), tv       );

    tv       = "000102030405060708090A0B0C0D".parseHex();
    tvPadded = "000102030405060708090A0B0C0D8000".parseHex();
    expect( ISO9797.pad(tv)        , tvPadded );
    expect( ISO9797.unpad(tvPadded), tv       );

    tv       = "000102030405060708090A0B0C0D0E".parseHex();
    tvPadded = "000102030405060708090A0B0C0D0E80".parseHex();
    expect( ISO9797.pad(tv)        , tvPadded );
    expect( ISO9797.unpad(tvPadded), tv       );

    tv       = "000102030405060708090A0B0C0D0E0F".parseHex();
    tvPadded = "000102030405060708090A0B0C0D0E0F8000000000000000".parseHex();
    expect( ISO9797.pad(tv)        , tvPadded );
    expect( ISO9797.unpad(tvPadded), tv       );
  });

  test('ISO9797 MAC algorithm 3', () {
    // Test vector from: https://github.com/rtyley/test-bc-java-cvsimport/blob/master/crypto/test/src/org/bouncycastle/jce/provider/test/MacTest.java#L31-L33
    var tvKmac  = "7CA110454A1A6E570131D9619DC1376E".parseHex();
    final tvIn  = Uint8List.fromList("Hello World !!!!".codeUnits);
    final tvOut = "F09B856213BAB83B".parseHex();
    expect( ISO9797.macAlg3(tvKmac, tvIn, padMsg: false), tvOut );

    // Test vectors from ICAO 9303 p11 - Appendix D to Part 11, section D.3
    tvKmac       = "7962D9ECE03D1ACD4C76089DCE131543".parseHex();
    final tvEifd = "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2".parseHex();
    expect( ISO9797.macAlg3(tvKmac, tvEifd), "5F1448EEA8AD90A7".parseHex() ); // function should pad the msg

    // Test vectors from ICAO 9303 p11 - Appendix D to Part 11, section D.3
    final tvEic = "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F".parseHex();
    expect( ISO9797.macAlg3(tvKmac, tvEic), "2F2D235D074D7449".parseHex() );

    // Test vectors from ICAO 9303 p11 - Appendix D to Part 11, section D.4.1
    tvKmac  = "F1CB1F1FB5ADF208806B89DC579DC1F8".parseHex();
    var tvN = "887022120C06C2270CA4020C800000008709016375432908C044F6".parseHex();
    expect( ISO9797.macAlg3(tvKmac, tvN), "BF8B92D635FF24F8".parseHex() );  // function should pad the msg

    // Test vectors from ICAO 9303 p11 - Appendix D to Part 11, section D.4.1
    var tvK = "887022120C06C22899029000".parseHex();
    expect( ISO9797.macAlg3(tvKmac, tvK), "FA855A5D4C50A8ED".parseHex() );  // function should pad the msg

    // Test vectors from ICAO 9303 p11 - Appendix D to Part 11, section D.4.2
    tvN = "887022120C06C2290CB0000080000000970104".parseHex();
    expect( ISO9797.macAlg3(tvKmac, tvN), "ED6705417E96BA55".parseHex() );  // function should pad the msg

    // Test vectors from ICAO 9303 p11 - Appendix D to Part 11, section D.4.2
    tvK = "887022120C06C22A8709019FF0EC34F992265199029000".parseHex();
    expect( ISO9797.macAlg3(tvKmac, tvK), "AD55CC17140B2DED".parseHex() );  // function should pad the msg

    // Test vectors from ICAO 9303 p11 - Appendix D to Part 11, section D.4.3
    tvN = "887022120C06C22B0CB0000480000000970112".parseHex();
    expect( ISO9797.macAlg3(tvKmac, tvN), "2EA28A70F3C7B535".parseHex() );  // function should pad the msg

    // Test vectors from ICAO 9303 p11 - Appendix D to Part 11, section D.4.3
    tvK = "887022120C06C22C871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A99029000".parseHex();
    expect( ISO9797.macAlg3(tvKmac, tvK), "C8B2787EAEA07D74".parseHex() );  // function should pad the msg
  });
}