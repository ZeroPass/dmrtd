//  Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:test/test.dart';

import 'package:dmrtd/src/lds/mrz.dart';
import 'package:dmrtd/src/extension/string_apis.dart';
import 'package:dmrtd/src/proto/bac.dart';
import 'package:dmrtd/src/proto/dba_keys.dart';

void main() {
  test('BAC key seed test', () {
    // Test vectors taken from: https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix D to Part 11  section D.2
    var mrz = MRZ(Uint8List.fromList("I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8".codeUnits));
    expect( DBAKeys.fromMRZ(mrz).keySeed , "b366ad857ddca2b08c0e299811714730".parseHex() );

    mrz = MRZ(Uint8List.fromList("I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<L898902C<3UTO6908061F9406236<<<<<<<2".codeUnits)); // Note: composite CD changed from 8 to 2
    expect( DBAKeys(mrz.documentNumber, mrz.dateOfBirth, mrz.dateOfExpiry).keySeed , "239ab9cb282daf66231dc5a4df6bfbae".parseHex() );

    mrz = MRZ(Uint8List.fromList("I<UTOD23145890<7349<<<<<<<<<<<3407127M9507122UTO<<<<<<<<<<<2STEVENSON<<PETER<JOHN<<<<<<<<<".codeUnits));
    expect( DBAKeys(mrz.documentNumber, mrz.dateOfBirth, mrz.dateOfExpiry).keySeed , "b366ad857ddca2b08c0e299811714730".parseHex() );

    mrz = MRZ(Uint8List.fromList("I<UTOL898902C<3<<<<<<<<<<<<<<<6908061F9406236UTO<<<<<<<<<<<2ERIKSSON<<ANNA<MARIA<<<<<<<<<<".codeUnits)); // Note: Composite CD changed from 1 to 2
    expect( DBAKeys.fromMRZ(mrz).keySeed , "239AB9CB282DAF66231DC5A4DF6BFBAE".parseHex() );
  });

  test('BAC session establishment test', () {
    // Test vectors taken from Appendix D.3 to Part 11 of ICAO 9303 p11 doc.
    // ref: https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf

    final tvMRZ      = MRZ(Uint8List.fromList("I<UTOL898902C<3<<<<<<<<<<<<<<<6908061F9406236UTO<<<<<<<<<<<2ERIKSSON<<ANNA<MARIA<<<<<<<<<<".codeUnits)); // Note: Composite CD changed from 1 to 2
    final tvKeySeed  = "239AB9CB282DAF66231DC5A4DF6BFBAE".parseHex();
    final tvKenc     = "AB94FDECF2674FDFB9B391F85D7F76F2".parseHex();
    final tvKmac     = "7962D9ECE03D1ACD4C76089DCE131543".parseHex();
    final tvRNDicc   = "4608F91988702212".parseHex();
    final tvRNDifd   = "781723860C06C226".parseHex();
    final tvKifd     = "0B795240CB7049B01C19B33E32804F0B".parseHex();
    final tvS        = "781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B".parseHex();
    final tvEifd     = "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2".parseHex();
    final tvMifd     = "5F1448EEA8AD90A7".parseHex();
    final tvCmdData  = "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7".parseHex();
    final tvRespData = "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449".parseHex();
    final tvEicc     = "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F".parseHex();
    final tvMicc     = "2F2D235D074D7449".parseHex();
    final tvR        = "4608F91988702212781723860C06C2260B4F80323EB3191CB04970CB4052790B".parseHex();
    final tvKicc     = "0B4F80323EB3191CB04970CB4052790B".parseHex();
    final tvKSenc    = "979EC13B1CBFE9DCD01AB0FED307EAE5".parseHex();
    final tvKSmac    = "F1CB1F1FB5ADF208806B89DC579DC1F8".parseHex();
    final tvSCC      = "887022120C06C226".parseHex();

    // Derive Kenc and Kmac
    final dbaKeys = DBAKeys.fromMRZ(tvMRZ);
    expect( dbaKeys.keySeed , tvKeySeed );
    expect( dbaKeys.encKey  , tvKenc    );
    expect( dbaKeys.macKey  , tvKmac    );

  	// Generate S, Eifd, Mifd and EA cmd data
    expect( BAC.generateS(RNDicc: tvRNDicc, RNDifd: tvRNDifd, Kifd: tvKifd), tvS );
    expect( BAC.E(Kenc: tvKenc, S: tvS), tvEifd );
    expect( BAC.MAC(Kmac: tvKmac, Eifd: tvEifd), tvMifd );
    expect( BAC.generateEAData(Eifd: tvEifd, Mifd: tvMifd), tvCmdData );

    // Extract Eicc and Micc from tvRespData.
    final pairEiccMicc = BAC.extractEiccAndMicc(ICCea_data: tvRespData);
    expect( pairEiccMicc.first, tvEicc );
    expect( pairEiccMicc.second, tvMicc );

    // Verify Eicc MAC (tvMicc), decrypt R from Eicc, verify RND.IFD and extract Kicc
    expect( BAC.verifyEicc(Eicc: tvEicc, Kmac: tvKmac, Micc: tvMicc), true );
    expect( BAC.D(Kdec: tvKenc, Eicc: tvEicc), tvR );
    expect( BAC.verifyRNDifdAndExtractKicc(RNDifd: tvRNDifd, R: tvR), tvKicc );

    // Calculate session keys KSenc, KSmac and SCC
    final pairKS = BAC.calculateSessionKeys(Kifd: tvKifd, Kicc: tvKicc);
    expect( pairKS.first , tvKSenc );
    expect( pairKS.second, tvKSmac );
    expect( BAC.calculateSCC(RNDifd: tvRNDifd, RNDicc: tvRNDicc).toBytes(), tvSCC );
  });
}