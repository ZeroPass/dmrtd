//  Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import 'package:test/test.dart';

import 'package:dmrtd/src/crypto/des.dart';
import 'package:dmrtd/src/extension/string_apis.dart';

void main() {
  final zeroIV = Uint8List(DESedeCipher.blockSize);

  test('DESedeCipher Encryption/Decryption with no padding', () {
    // Test vectors from ICAO 9303 p11 - Appendix D to Part 11, section D.3
    final tvKenc = "AB94FDECF2674FDFB9B391F85D7F76F2".parseHex();
    final tvS    = "781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B".parseHex();
    final tvEifd = "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2".parseHex();
    final Eifd   = DESedeCipher(key: tvKenc, iv: zeroIV).encrypt(tvS, padData: false);
    expect( Eifd, tvEifd );

    final dS = DESedeCipher(key: tvKenc, iv: zeroIV).decrypt(Eifd, paddedData: false);
    expect( dS, tvS );

    // Test vectors from ICAO 9303 p11 - Appendix D to Part 11, section D.3
    final tvR   = "4608F91988702212781723860C06C2260B4F80323EB3191CB04970CB4052790B".parseHex();
    final tvEic = "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F".parseHex();
    final Eic   = DESedeEncrypt(key: tvKenc, iv: zeroIV, data: tvR, padData: false);
    expect( Eic, tvEic );

    final dR = DESedeDecrypt(key: tvKenc, iv: zeroIV, edata: Eic, paddedData: false);
    expect( dR, tvR );
  });

  test('DESedeCipher Encryption/Decryption with padding', () {
    // Test vectors from ICAO 9303 p11 - Appendix D to Part 11, section D.4.1
    final tvKSenc  = "979EC13B1CBFE9DCD01AB0FED307EAE5".parseHex();
    var tvData     = "011E".parseHex();
    var tvEData    = "6375432908C044F6".parseHex();

    var edata = DESedeCipher(key: tvKSenc, iv: zeroIV).encrypt(tvData, padData: true);
    expect( edata, tvEData );

    var data = DESedeCipher(key: tvKSenc, iv: zeroIV).decrypt(edata, paddedData: true);
    expect( data, tvData );

    // Test vectors from ICAO 9303 p11 - Appendix D to Part 11, section D.4.2
    tvData  = "60145F01".parseHex();
    tvEData = "9FF0EC34F9922651".parseHex();
    edata = DESedeCipher(key: tvKSenc, iv: zeroIV).encrypt(tvData); // should be padded by default
    expect( edata, tvEData );

    data = DESedeCipher(key: tvKSenc, iv: zeroIV).decrypt(edata);   // should be unpadded by default
    expect( data, tvData );

    // Test vectors from ICAO 9303 p11 - Appendix D to Part 11, section D.4.3
    tvData  = "04303130365F36063034303030305C026175".parseHex();
    tvEData = "FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A".parseHex();
    edata   = DESedeEncrypt(key: tvKSenc, iv: zeroIV, data: tvData); // should be padded by default
    expect( edata, tvEData );

    data = DESedeDecrypt(key: tvKSenc, iv: zeroIV, edata: edata);   // should be unpadded by default
    expect( data, tvData );
  });
}