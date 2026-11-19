//  Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.

import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';
import 'package:pointycastle/ecc/api.dart';

import '../lds/asn1ObjectIdentifiers.dart';
import '../utils.dart';

abstract class PublicKeyPACE {
  TOKEN_AGREEMENT_ALGO  algo;

  TOKEN_AGREEMENT_ALGO get agreementAlgorithm => algo;

  PublicKeyPACE({required this.algo});

  Uint8List toBytes();

  Uint8List toRelavantBytes();

  String toString();
}

class PublicKeyPACEeCDH extends PublicKeyPACE{
  final BigInt _x;
  final BigInt _y;

  /// Length in bytes of each encoded coordinate, ceil(fieldBits / 8).
  /// Coordinates are encoded with FE2OS (BSI TR-03111 3.1.3), i.e. left-padded
  /// with zeros to this length. If null, the minimal encoding is used.
  final int? coordinateLength;

  PublicKeyPACEeCDH({required BigInt x, required BigInt y, this.coordinateLength}):
        _x = x,
        _y = y,
        super(algo: TOKEN_AGREEMENT_ALGO.ECDH);

  PublicKeyPACEeCDH.fromECPoint({required ECPoint public}):
        _x = public.x!.toBigInteger()!,
        _y = public.y!.toBigInteger()!,
        coordinateLength = (public.curve.fieldSize + 7) ~/ 8,
        super(algo: TOKEN_AGREEMENT_ALGO.ECDH);

  BigInt get x => _x;
  BigInt get y => _y;

  Uint8List get xBytes => _fe2os(_x);
  Uint8List get yBytes => _fe2os(_y);

  Uint8List _fe2os(BigInt value) {
    final bytes = Utils.bigIntToUint8List(bigInt: value);
    final length = coordinateLength;
    if (length == null || bytes.length >= length) {
      return bytes;
    }
    return Uint8List(length)..setRange(length - bytes.length, length, bytes);
  }

  @override
  Uint8List toBytes() {
    return Uint8List.fromList([...xBytes, ...yBytes]);
  }

  PublicKeyPACEeCDH.fromHex({required Uint8List hexKey}):
        _x = Utils.uint8ListToBigInt(hexKey.sublist(0, hexKey.length ~/ 2)),
        _y = Utils.uint8ListToBigInt(hexKey.sublist(hexKey.length ~/ 2)),
        coordinateLength = hexKey.length ~/ 2,
        super(algo: TOKEN_AGREEMENT_ALGO.ECDH);

  @override
  Uint8List toRelavantBytes() {
    return xBytes;
  }

  @override
  String toString() {
    return "X: ${xBytes.hex()}\nY: ${yBytes.hex()}";
  }
}

class PublicKeyPACEdH extends PublicKeyPACE{
  final Uint8List _pub;
  PublicKeyPACEdH({required Uint8List pub}):
        _pub = pub,
        super(algo: TOKEN_AGREEMENT_ALGO.DH);

  Uint8List get pub => _pub;


  @override
  Uint8List toBytes() {
    return _pub;
  }

  @override
  Uint8List toRelavantBytes() {
    return _pub;
  }

  @override
  String toString() {
    return _pub.hex();
  }
}