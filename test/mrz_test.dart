//  Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dmrtd/src/lds/mrz.dart';

import 'utils.dart';

void main() {
  test('Check digit test', () {
    // Test vectors taken from ICAO 9303-p3 Appendix A to part 3
    expect( MRZ.calculateCheckDigit('520727')                                            , 3 ); // Example 1
    expect( MRZ.calculateCheckDigit('AB2134<<<')                                         , 5 ); // Example 2
    expect( MRZ.calculateCheckDigit('HA672242<658022549601086<<<<<<<<<<<<<<0' )          , 8 ); // Example 3
    expect( MRZ.calculateCheckDigit('D231458907<<<<<<<<<<<<<<<34071279507122<<<<<<<<<<<'), 2 ); // Example 4
    expect( MRZ.calculateCheckDigit('HA672242<658022549601086<<<<<<<0')                  , 8 ); // Example 5
  });

  group('MRZ parsing', () {
    test('parsing TD1', () {
      // Test vector from: https://www.icao.int/publications/Documents/9303_p5_cons_en.pdf  Appendix A to Part 5
      MRZ mrz = MRZ(Uint8List.fromList("I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<".codeUnits));
      expect( mrz.version       , MRZVersion.td1        );
      expect( mrz.documentCode  , 'I'                   );
      expect( mrz.documentNumber, 'D23145890'           );
      expect( mrz.country       , 'UTO'                 );
      expect( mrz.nationality   , 'UTO'                 );
      expect( mrz.firstName     , 'ANNA MARIA'          );
      expect( mrz.lastName      , 'ERIKSSON'            );
      expect( mrz.gender        , 'F'                   );
      expect( mrz.dateOfBirth   , DateTime(1974, 8, 12) );
      expect( mrz.dateOfExpiry  , DateTime(2012, 4, 15) );
      expect( mrz.optionalData  , ''                    );
      expect( mrz.optionalData2 , ''                    );

      // Extended Document number test.
      // Test vector from: https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix D to Part 11 Section D.2
      mrz = MRZ(Uint8List.fromList("I<UTOD23145890<7349<<<<<<<<<<<3407127M9507122UTO<<<<<<<<<<<2STEVENSON<<PETER<JOHN<<<<<<<<<".codeUnits));
      expect( mrz.version       , MRZVersion.td1        );
      expect( mrz.documentCode  , 'I'                   );
      expect( mrz.documentNumber, 'D23145890734'        );
      expect( mrz.country       , 'UTO'                 );
      expect( mrz.nationality   , 'UTO'                 );
      expect( mrz.firstName     , 'PETER JOHN'          );
      expect( mrz.lastName      , 'STEVENSON'           );
      expect( mrz.gender        , 'M'                   );
      expect( mrz.dateOfBirth   , DateTime(1934, 7, 12) );
      expect( mrz.dateOfExpiry  , DateTime(1995, 7, 12) );
      expect( mrz.optionalData  , ''                    );
      expect( mrz.optionalData2 , null                  );
    });

    test('parsing TD2', () {
      // Test vector from: https://www.icao.int/publications/Documents/9303_p6_cons_en.pdf Appendix A to Part 6
      MRZ mrz = MRZ(Uint8List.fromList("I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<6".codeUnits));
      expect( mrz.version       , MRZVersion.td2        );
      expect( mrz.documentCode  , 'I'                   );
      expect( mrz.documentNumber, 'D23145890'           );
      expect( mrz.country       , 'UTO'                 );
      expect( mrz.nationality   , 'UTO'                 );
      expect( mrz.firstName     , 'ANNA MARIA'          );
      expect( mrz.lastName      , 'ERIKSSON'            );
      expect( mrz.gender        , 'F'                   );
      expect( mrz.dateOfBirth   , DateTime(1974, 8, 12) );
      expect( mrz.dateOfExpiry  , DateTime(2012, 4, 15) );
      expect( mrz.optionalData  , ''                    );
      expect( mrz.optionalData2 , null                  );

      // Extended Document number test.
      // Test vector from: https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix D to Part 11 Section D.2
      mrz = MRZ(Uint8List.fromList("I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8".codeUnits));
      expect( mrz.version       , MRZVersion.td2        );
      expect( mrz.documentCode  , 'I'                   );
      expect( mrz.documentNumber, 'D23145890734'        );
      expect( mrz.country       , 'UTO'                 );
      expect( mrz.nationality   , 'UTO'                 );
      expect( mrz.firstName     , 'PETER JOHN'          );
      expect( mrz.lastName      , 'STEVENSON'           );
      expect( mrz.gender        , 'M'                   );
      expect( mrz.dateOfBirth   , DateTime(1934, 7, 12) );
      expect( mrz.dateOfExpiry  , DateTime(1995, 7, 12) );
      expect( mrz.optionalData  , ''                    );
      expect( mrz.optionalData2 , null                  );
    });

    test('parsing TD3', () {
      // Test vector from: https://www.icao.int/publications/Documents/9303_p4_cons_en.pdf Appendix A To Part 4
      MRZ mrz = MRZ(Uint8List.fromList("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10".codeUnits));
      expect( mrz.version       , MRZVersion.td3        );
      expect( mrz.documentCode  , 'P'                   );
      expect( mrz.documentNumber, 'L898902C3'           );
      expect( mrz.country       , 'UTO'                 );
      expect( mrz.nationality   , 'UTO'                 );
      expect( mrz.firstName     , 'ANNA MARIA'          );
      expect( mrz.lastName      , 'ERIKSSON'            );
      expect( mrz.gender        , 'F'                   );
      expect( mrz.dateOfBirth   , DateTime(1974, 8, 12) );
      expect( mrz.dateOfExpiry  , DateTime(2012, 4, 15) );
      expect( mrz.optionalData  , 'ZE184226B'           );
      expect( mrz.optionalData2 , null                  );

      mrz = MRZ(Uint8List.fromList("P<D<<SCHMIDT<<FINN<<<<<<<<<<<<<<<<<<<<<<<<<<AA89BXHZ56D<<7503201M2511188<<<<<<<<<<<<<<<8".codeUnits));
      expect( mrz.version       , MRZVersion.td3         );
      expect( mrz.documentCode  , 'P'                    );
      expect( mrz.documentNumber, 'AA89BXHZ5'            );
      expect( mrz.country       , 'D'                    );
      expect( mrz.nationality   , 'D'                    );
      expect( mrz.firstName     , 'FINN'                 );
      expect( mrz.lastName      , 'SCHMIDT'              );
      expect( mrz.gender        , 'M'                    );
      expect( mrz.dateOfBirth   , DateTime(1975, 3, 20)  );
      expect( mrz.dateOfExpiry  , DateTime(2025, 11, 18) );
      expect( mrz.optionalData  , ''                     );
      expect( mrz.optionalData2 , null                   );
    });

    test('fuzz tests', () {
      expect( ()=> MRZ(Uint8List(0)), throwsMRZParseError(message: "Invalid MRZ data") );

      // TD1
      expect( ()=> MRZ(Uint8List.fromList("I<UTOD231458902<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<".codeUnits)), throwsMRZParseError(message: "Document Number check digit mismatch") );
      expect( ()=> MRZ(Uint8List.fromList("I<UTOD231458907<<<<<<<<<<<<<<<7408123F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<".codeUnits)), throwsMRZParseError(message: "Data of Birth check digit mismatch")   );
      expect( ()=> MRZ(Uint8List.fromList("I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204158UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<".codeUnits)), throwsMRZParseError(message: "Data of Expiry check digit mismatch")  );
      expect( ()=> MRZ(Uint8List.fromList("I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<5ERIKSSON<<ANNA<MARIA<<<<<<<<<>".codeUnits)), throwsMRZParseError(message: "Composite check digit mismatch")       );
      // TD2
      expect( ()=> MRZ(Uint8List.fromList("I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458908UTO7408122F1204159<<<<<<<6".codeUnits)), throwsMRZParseError(message: "Document Number check digit mismatch") );
      expect( ()=> MRZ(Uint8List.fromList("I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408123F1204159<<<<<<<6".codeUnits)), throwsMRZParseError(message: "Data of Birth check digit mismatch")   );
      expect( ()=> MRZ(Uint8List.fromList("I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204158<<<<<<<6".codeUnits)), throwsMRZParseError(message: "Data of Expiry check digit mismatch")  );
      expect( ()=> MRZ(Uint8List.fromList("I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<7".codeUnits)), throwsMRZParseError(message: "Composite check digit mismatch")       );
      // TD3
      expect( ()=> MRZ(Uint8List.fromList("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C35UTO7408122F1204159ZE184226B<<<<<10".codeUnits)), throwsMRZParseError(message: "Document Number check digit mismatch") );
      expect( ()=> MRZ(Uint8List.fromList("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408123F1204159ZE184226B<<<<<10".codeUnits)), throwsMRZParseError(message: "Data of Birth check digit mismatch")   );
      expect( ()=> MRZ(Uint8List.fromList("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204158ZE184226B<<<<<10".codeUnits)), throwsMRZParseError(message: "Data of Expiry check digit mismatch")  );
      expect( ()=> MRZ(Uint8List.fromList("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<20".codeUnits)), throwsMRZParseError(message: "Optional data check digit mismatch")   );
      expect( ()=> MRZ(Uint8List.fromList("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<12".codeUnits)), throwsMRZParseError(message: "Composite check digit mismatch")       );
    });
  });
}