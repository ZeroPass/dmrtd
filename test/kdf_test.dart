// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'package:test/test.dart';

import 'package:dmrtd/src/crypto/kdf.dart';
import 'package:dmrtd/src/extension/string_apis.dart';

void main() {

  test('Derive key for DESede and ISO/IEC 9797 MAC Algorithm 3', () {
    // Test vectors taken from ICAO 9303 Appendix D to Part 11
    // ignore: non_constant_identifier_names
    var Kseed = "239AB9CB282DAF66231DC5A4DF6BFBAE".parseHex();
    expect( DeriveKey.desEDE(Kseed)         , "AB94FDECF2674FDFB9B391F85D7F76F2".parseHex() );
    expect( DeriveKey.iso9797MacAlg3(Kseed) , "7962D9ECE03D1ACD4C76089DCE131543".parseHex() );

    Kseed = "0036D272F5C350ACAC50C3F572D23600".parseHex();
    expect( DeriveKey.desEDE(Kseed)         , "979EC13B1CBFE9DCD01AB0FED307EAE5".parseHex() );
    expect( DeriveKey.iso9797MacAlg3(Kseed) , "F1CB1F1FB5ADF208806B89DC579DC1F8".parseHex() );
  });

  test('Derive key for AES128 and CMAC128', () {
    // Test vectors taken from ICAO 9303 Appendix G to Part 11
    var sharedSecret = "28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925".parseHex();
    expect( DeriveKey.aes128(sharedSecret)  , "F5F0E35C0D7161EE6724EE513A0D9A7F".parseHex() );
    expect( DeriveKey.cmac128(sharedSecret) , "FE251C7858B356B24514B3BD5F4297D1".parseHex() );

    sharedSecret = "6BABC7B3A72BCD7EA385E4C62DB2625BD8613B24149E146A629311C4CA6698E38B834B6A9E9CD7184BA8834AFF5043D436950C4C1E7832367C10CB8C314D40E5990B0DF7013E64B4549E2270923D06F08CFF6BD3E977DDE6ABE4C31D55C0FA2E465E553E77BDF75E3193D3834FC26E8EB1EE2FA1E4FC97C18C3F6CFFFE2607FD".parseHex();
    expect( DeriveKey.aes128(sharedSecret)  , "2F7F46ADCC9E7E521B45D192FAFA9126".parseHex() );
    expect( DeriveKey.cmac128(sharedSecret) , "805A1D27D45A5116F73C54469462B7D8".parseHex() );

    // Test vectors taken from ICAO 9303 Appendix I to Part 11
    sharedSecret = "67950559D0C06B4D4B86972D14460837461087F8419FDBC36AAF6CEAAC462832".parseHex();
    expect( DeriveKey.aes128(sharedSecret)  , "0A9DA4DB03BDDE39FC5202BC44B2E89E".parseHex() );
    expect( DeriveKey.cmac128(sharedSecret) , "4B1C06491ED5140CA2B537D344C6C0B1".parseHex() );
  });
}