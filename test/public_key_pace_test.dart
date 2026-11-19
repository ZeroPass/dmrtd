import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:pointycastle/ecc/api.dart';

import 'package:dmrtd/src/proto/ecdh_pace.dart';
import 'package:dmrtd/src/proto/public_key_pace.dart';
import 'package:dmrtd/src/extension/string_apis.dart';

Uint8List bigIntToBytes(BigInt v, int length) =>
    Uint8List.fromList(List.generate(length, (i) => ((v >> (8 * (length - 1 - i))) & BigInt.from(0xFF)).toInt()));

void main() {
  // EC coordinates must be encoded with FE2OS, i.e. with a fixed length of
  // ceil(fieldBits / 8) bytes (BSI TR-03111 3.1.3; ICAO 9303-11 4.4.3.4, 9.7.1)

  test('ECDH public key coordinates are left-padded to coordinate length', () {
    final key = PublicKeyPACEeCDH(x: BigInt.from(0x05), y: BigInt.parse("01" * 31, radix: 16), coordinateLength: 32);
    expect(key.xBytes, Uint8List(32)..[31] = 0x05);
    expect(key.yBytes, ("00" + "01" * 31).parseHex());
    expect(key.toBytes().length, 64);
    expect(key.toRelavantBytes().length, 32);
  });

  test('ECDH public key from bytes keeps leading zero bytes', () {
    final bytes = ("00" * 2 + "AB" * 30 + "00" + "CD" * 31).parseHex();
    final key = PublicKeyPACEeCDH.fromHex(hexKey: bytes);
    expect(key.toBytes(), bytes);
    expect(key.toRelavantBytes(), bytes.sublist(0, 32));
  });

  test('ECDH public key without coordinate length uses minimal encoding', () {
    final key = PublicKeyPACEeCDH(x: BigInt.from(0x0102), y: BigInt.from(0x03));
    expect(key.toBytes(), "010203".parseHex());
  });

  test('BrainpoolP384r1 point with leading zero byte in x is encoded with 48 bytes', () {
    final dp = DomainParameterSelectorECDH.getDomainParameter(id: 16);
    final G = dp.domainParameters.G;

    // find a small scalar k such that x(k*G) has a leading zero byte
    var k = BigInt.one;
    ECPoint p = G;
    while (p.x!.toBigInteger()!.bitLength > 47 * 8) {
      k += BigInt.one;
      p = (p + G)!;
    }

    final x = p.x!.toBigInteger()!;
    final y = p.y!.toBigInteger()!;
    final expected = Uint8List.fromList([...bigIntToBytes(x, 48), ...bigIntToBytes(y, 48)]);
    expect(expected[0], 0x00);

    // point -> public key data
    final fromPoint = ECDHPace.ecPointToList(point: p);
    expect(fromPoint.toBytes(), expected);
    expect(fromPoint.toRelavantBytes(), expected.sublist(0, 48));
    expect(PublicKeyPACEeCDH.fromECPoint(public: p).toBytes(), expected);

    // terminal key pair with the same private key
    dp.generateKeyPairFromPriv(privKey: bigIntToBytes(k, 48));
    expect(dp.getPubKey().toBytes(), expected);
  });

  test('ECDH public key encoding has fixed length for random points', () {
    final rnd = Random(3);
    for (final id in [13, 16]) {
      final dp = DomainParameterSelectorECDH.getDomainParameter(id: id);
      final params = dp.domainParameters;
      final length = (params.curve.fieldSize + 7) ~/ 8;
      for (var i = 0; i < 50; i++) {
        final d = BigInt.parse(List.generate(length, (_) => rnd.nextInt(256).toRadixString(16).padLeft(2, '0')).join(), radix: 16) % params.n;
        // force some coordinates to be short by using tiny scalars
        final scalar = i < 10 ? BigInt.from(i + 1) : d;
        final p = (params.G * scalar)!;
        final key = ECDHPace.ecPointToList(point: p);
        final bytes = key.toBytes();
        expect(bytes.length, 2 * length);
        expect(bytes.sublist(0, length), bigIntToBytes(p.x!.toBigInteger()!, length));
        expect(bytes.sublist(length), bigIntToBytes(p.y!.toBigInteger()!, length));
        expect(PublicKeyPACEeCDH.fromHex(hexKey: bytes).toBytes(), bytes);
      }
    }
  });
}
