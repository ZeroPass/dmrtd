// Created by Crt Vavros, copyright © 2021 ZeroPass. All rights reserved.
import 'package:test/test.dart';

import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/extensions.dart';

void main() {
  //  Test vectors from Appendix A to the part 10 of ICAO 9393 p10 doc
  test('Test parsing/encoding EF.COM', () {
    // A.1 - test case 1
    var tvEfCom = "60165F0104303130375F36063034303030305C046175766C".parseHex();
    var efCom = EfCOM.fromBytes(tvEfCom);
    expect( efCom.toBytes()                    , tvEfCom  );
    expect( efCom.version                      , "0107"   );
    expect( efCom.uincodeVersion               , "040000" );
    expect( efCom.dgTags.length                , 4        );
    expect( efCom.dgTags.contains(DgTag(0x61)) , true     );
    expect( efCom.dgTags.contains(DgTag(0x75)) , true     );
    expect( efCom.dgTags.contains(DgTag(0x76)) , true     );
    expect( efCom.dgTags.contains(DgTag(0x6C)) , true     );

    // A.1 - test case 2
    tvEfCom = "60165F0104313539395F36063034303030305C046175766C".parseHex();
    efCom = EfCOM.fromBytes(tvEfCom);
    expect( efCom.toBytes()                    , tvEfCom  );
    expect( efCom.version                      , "1599"   );
    expect( efCom.uincodeVersion               , "040000" );
    expect( efCom.dgTags.length                , 4        );
    expect( efCom.dgTags.contains(DgTag(0x61)) , true     );
    expect( efCom.dgTags.contains(DgTag(0x75)) , true     );
    expect( efCom.dgTags.contains(DgTag(0x76)) , true     );
    expect( efCom.dgTags.contains(DgTag(0x6C)) , true     );
  });

  test('Test parsing/encoding EF.DG1', () {
    // A.2.1 - Note: composite CD was changed from 4 to 8
    final tvDG1TD1 = "615D5F1F5A493C4E4C44584938353933354638363939393939393939303C3C3C3C3C3C3732303831343846313130383236384E4C443C3C3C3C3C3C3C3C3C3C3C3856414E3C4445523C535445454E3C3C4D415249414E4E453C4C4F55495345".parseHex();
    var dg1 = EfDG1.fromBytes(tvDG1TD1);
    expect( dg1.toBytes()         , tvDG1TD1              );
    expect( dg1.mrz.version       , MRZVersion.td1        );
    expect( dg1.mrz.documentCode  , 'I'                   );
    expect( dg1.mrz.documentNumber, 'XI85935F8'           );
    expect( dg1.mrz.country       , 'NLD'                 );
    expect( dg1.mrz.nationality   , 'NLD'                 );
    expect( dg1.mrz.firstName     , 'MARIANNE LOUISE'     );
    expect( dg1.mrz.lastName      , 'VAN DER STEEN'       );
    expect( dg1.mrz.sex           , 'F'                   );
    expect( dg1.mrz.dateOfBirth   , DateTime(1972, 8, 14) );
    expect( dg1.mrz.dateOfExpiry  , DateTime(2011, 8, 26) );
    expect( dg1.mrz.optionalData  , '999999990'           );
    expect( dg1.mrz.optionalData2 , ''                    );

    // A.2.2 - Note: The serialized MRZ in doc is malformed!
    //               The data was modified:
    //                 - by removing extra '<' right of name field and optional data
    //                 - removed last invalid digit '4',
    //                 - CD for date of birth was changed to 1
    //                 - CD for date of expiry was changed to 2
    //                 - CD for doc. no. was changed to 2
    //                 - CD for composite was changed to0
    final tvDG1TD2 = "614B5F1F48493C415441534D4954483C3C4A4F484E3C543C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3132333435363738393C484D44373430363232314D31303132333132303132323C3C3C30".parseHex();
    dg1 = EfDG1.fromBytes(tvDG1TD2);
    expect( dg1.toBytes()         , tvDG1TD2               );
    expect( dg1.mrz.version       , MRZVersion.td2         );
    expect( dg1.mrz.documentCode  , 'I'                    );
    expect( dg1.mrz.documentNumber, '123456789012'         );
    expect( dg1.mrz.country       , 'ATA'                  );
    expect( dg1.mrz.nationality   , 'HMD'                  );
    expect( dg1.mrz.firstName     , 'JOHN T'               );
    expect( dg1.mrz.lastName      , 'SMITH'                );
    expect( dg1.mrz.sex           , 'M'                    );
    expect( dg1.mrz.dateOfBirth   , DateTime(1974, 6, 22)  );
    expect( dg1.mrz.dateOfExpiry  , DateTime(2010, 12, 31) );
    expect( dg1.mrz.optionalData  , ''                     );
    expect( dg1.mrz.optionalData2 , null                   );
  });
}