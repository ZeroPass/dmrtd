//  Created by smlu on 07/02/2020.
//  Copyright © 2020 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dmrtd/src/lds/mrz.dart';

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
      expect( mrz.sex           , 'F'                   );
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
      expect( mrz.sex           , 'M'                   );
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
      expect( mrz.sex           , 'F'                   );
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
      expect( mrz.sex           , 'M'                   );
      expect( mrz.dateOfBirth   , DateTime(1934, 7, 12) );
      expect( mrz.dateOfExpiry  , DateTime(1995, 7, 12) );
      expect( mrz.optionalData  , null                  );
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
      expect( mrz.sex           , 'F'                   );
      expect( mrz.dateOfBirth   , DateTime(1974, 8, 12) );
      expect( mrz.dateOfExpiry  , DateTime(2012, 4, 15) );
      expect( mrz.optionalData  , 'ZE184226B'           );
      expect( mrz.optionalData2 , null                  );
    });
  });
}