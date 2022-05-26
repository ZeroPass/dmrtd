// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/proto/ssc.dart';
import 'package:test/test.dart';

void main() {

  test('SSC test', () {

    // Test case 1
    var tvSSC = SSC('00'.parseHex(), 8);
    expect( tvSSC.toBytes(), '00'.parseHex() );

    // Test case 2
    tvSSC = SSC('01'.parseHex(), 16);
    expect( tvSSC.toBytes(), '0001'.parseHex() );

    // Test case 3
    tvSSC = SSC('FF'.parseHex(), 16);
    expect( tvSSC.toBytes(), '00FF'.parseHex() );

    tvSSC.increment();
    expect( tvSSC.toBytes(), '0100'.parseHex() );

    // Test case 4 - overflow
    tvSSC = SSC('FFFF'.parseHex(), 16);
    tvSSC.increment();
    expect( tvSSC.toBytes(), '0000'.parseHex() );

    // Test case 5
    tvSSC = SSC('02FFFFFFFFFFFF01'.parseHex(), 64);
    expect( tvSSC.toBytes(), '02FFFFFFFFFFFF01'.parseHex() );

    tvSSC.increment();
    expect( tvSSC.toBytes(), '02FFFFFFFFFFFF02'.parseHex() );

    // Test case 6 - overflow
    tvSSC = SSC('FFFFFFFFFFFFFFFE'.parseHex(), 64);
    tvSSC.increment();
    tvSSC.increment();
    expect( tvSSC.toBytes(), '0000000000000000'.parseHex() );

    // Test case 7
    tvSSC = SSC('0102030405060708090A0B0C0D0E0FFE'.parseHex(), 128);
    expect( tvSSC.toBytes(), '0102030405060708090A0B0C0D0E0FFE'.parseHex() );

    tvSSC.increment();
    expect(tvSSC.toBytes(), '0102030405060708090A0B0C0D0E0FFF'.parseHex());

    tvSSC.increment();
    expect( tvSSC.toBytes(), '0102030405060708090A0B0C0D0E1000'.parseHex() );

    // Test case 8
    tvSSC = SSC('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'.parseHex(), 128);
    expect( tvSSC.toBytes(), '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'.parseHex() );

    tvSSC.increment();
    expect( tvSSC.toBytes(), '02000000000000000000000000000000'.parseHex() );

    // Test case 9 - overflow
    tvSSC = SSC('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'.parseHex(), 128);
    expect( tvSSC.toBytes(), 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'.parseHex() );

    tvSSC.increment();
    expect( tvSSC.toBytes(), '00000000000000000000000000000000'.parseHex() );

    // Test case 10 - exceptions
    expect( () => SSC('00'.parseHex(), 7) , throwsArgumentError ); // wrong bit size - not multiple of 8
    expect( () => SSC('0100'.parseHex(), 8) , throwsArgumentError ); // too big

    tvSSC = SSC('0000000000000000000000000001'.parseHex(), 8);
    expect( tvSSC.toBytes() , "01".parseHex() ); // should not throw

    // Test case 11
    // Test vectors from section Appendix D.4 to the part 11 of ICAO 9303 p11
    // ref: https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
    tvSSC = DESedeSSC('887022120C06C226'.parseHex());
    expect( tvSSC.toBytes(), '887022120C06C226'.parseHex() );

    tvSSC.increment();
    expect( tvSSC.toBytes(), '887022120C06C227'.parseHex() );

    tvSSC.increment();
    expect( tvSSC.toBytes(), '887022120C06C228'.parseHex() );

    tvSSC.increment();
    expect( tvSSC.toBytes(), '887022120C06C229'.parseHex() );

    tvSSC.increment();
    expect( tvSSC.toBytes(), '887022120C06C22A'.parseHex() );

    tvSSC.increment();
    expect( tvSSC.toBytes(), '887022120C06C22B'.parseHex() );

    tvSSC.increment();
    expect( tvSSC.toBytes(), '887022120C06C22C'.parseHex() );
  });
}