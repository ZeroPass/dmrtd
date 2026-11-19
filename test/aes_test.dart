import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:pointycastle/export.dart';

import 'package:dmrtd/src/crypto/aes.dart';
import 'package:dmrtd/src/extension/string_apis.dart';

// Reference AES-CMAC (NIST SP 800-38B) built on pointycastle's AES-CBC,
// used to cross-check AESCipher.calculateCMAC with random inputs.
Uint8List referenceCMAC(Uint8List key, Uint8List data) {
  final aes = AESEngine()..init(true, KeyParameter(key));
  final l = aes.process(Uint8List(16));

  BigInt toBigInt(Uint8List b) => b.fold(BigInt.zero, (v, e) => (v << 8) | BigInt.from(e));
  Uint8List toBytes(BigInt v) => Uint8List.fromList(List.generate(16, (i) => ((v >> (8 * (15 - i))) & BigInt.from(0xFF)).toInt()));
  final mask = (BigInt.one << 128) - BigInt.one;
  BigInt dbl(BigInt v) => ((v << 1) & mask) ^ ((v >> 127) == BigInt.one ? BigInt.from(0x87) : BigInt.zero);

  final k1 = dbl(toBigInt(l));
  final k2 = dbl(k1);

  final isComplete = data.isNotEmpty && data.length % 16 == 0;
  final m = isComplete
      ? Uint8List.fromList(data)
      : Uint8List.fromList([...data, 0x80, ...List.filled(15 - data.length % 16, 0)]);
  final subkey = toBytes(isComplete ? k1 : k2);
  for (var i = 0; i < 16; i++) {
    m[m.length - 16 + i] ^= subkey[i];
  }

  final cbc = CBCBlockCipher(AESEngine())..init(true, ParametersWithIV(KeyParameter(key), Uint8List(16)));
  final out = Uint8List(m.length);
  for (var off = 0; off < m.length; off += 16) {
    cbc.processBlock(m, off, out, off);
  }
  return out.sublist(out.length - 16);
}

void main() {
  final message = ("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").parseHex();

  test('AES-CMAC-128 (NIST SP 800-38B D.1 / RFC 4493)', () {
    final key = "2b7e151628aed2a6abf7158809cf4f3c".parseHex();
    final aes = AESCipher128();
    // MAC is truncated to 8 bytes (ICAO 9303-11 9.8.7.2)
    expect(aes.calculateCMAC(data: message.sublist(0, 0) , key: key), "bb1d6929e9593728".parseHex());
    expect(aes.calculateCMAC(data: message.sublist(0, 16), key: key), "070a16b46b4d4144".parseHex());
    expect(aes.calculateCMAC(data: message.sublist(0, 40), key: key), "dfa66747de9ae630".parseHex());
    expect(aes.calculateCMAC(data: message.sublist(0, 64), key: key), "51f0bebf7e3b9d92".parseHex());
  });

  test('AES-CMAC-192 (NIST SP 800-38B D.2)', () {
    final key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b".parseHex();
    final aes = AESCipher192();
    expect(aes.calculateCMAC(data: message.sublist(0, 0) , key: key), "d17ddf46adaacde5".parseHex());
    expect(aes.calculateCMAC(data: message.sublist(0, 16), key: key), "9e99a7bf31e71090".parseHex());
    expect(aes.calculateCMAC(data: message.sublist(0, 40), key: key), "8a1de5be2eb31aad".parseHex());
    expect(aes.calculateCMAC(data: message.sublist(0, 64), key: key), "a1d5df0eed790f79".parseHex());
  });

  test('AES-CMAC-256 (NIST SP 800-38B D.3)', () {
    final key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".parseHex();
    final aes = AESCipher256();
    expect(aes.calculateCMAC(data: message.sublist(0, 0) , key: key), "028962f61b7bf89e".parseHex());
    expect(aes.calculateCMAC(data: message.sublist(0, 16), key: key), "28a7023f452e8f82".parseHex());
    expect(aes.calculateCMAC(data: message.sublist(0, 40), key: key), "aaf3d8f1de5640c2".parseHex());
    expect(aes.calculateCMAC(data: message.sublist(0, 64), key: key), "e1992190549f6ed5".parseHex());
  });

  test('AES-CMAC-128 matches pointycastle CMac for random inputs', () {
    final rnd = Random(1);
    for (var i = 0; i < 200; i++) {
      final key = Uint8List.fromList(List.generate(16, (_) => rnd.nextInt(256)));
      final data = Uint8List.fromList(List.generate(rnd.nextInt(100), (_) => rnd.nextInt(256)));
      final expected = (CMac(BlockCipher('AES'), 64)..init(KeyParameter(key))).process(data);
      expect(AESCipher128().calculateCMAC(data: data, key: key), expected);
    }
  });

  test('AES-CMAC matches reference implementation for random keys (128/192/256) and inputs', () {
    final rnd = Random(2);
    for (var i = 0; i < 300; i++) {
      final key = Uint8List.fromList(List.generate([16, 24, 32][rnd.nextInt(3)], (_) => rnd.nextInt(256)));
      final data = Uint8List.fromList(List.generate(rnd.nextInt(100), (_) => rnd.nextInt(256)));
      expect(AESCipher256().calculateCMAC(data: data, key: key), referenceCMAC(key, data).sublist(0, 8));
    }
  });

  test('AES-CMAC rejects invalid key length', () {
    expect(() => AESCipher128().calculateCMAC(data: Uint8List(16), key: Uint8List(20)),
        throwsA(isA<AESCipherError>()));
  });
}
