import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:dmrtd/src/extension/logging_apis.dart';
import 'package:meta/meta.dart';
import "package:logging/logging.dart";

import '../utils.dart';


extension RandomExtension on Random {
  BigInt nextBigInt(int bitLength) {
    BytesBuilder builder = BytesBuilder();
    if (bitLength % 8 != 0) {
      throw ('Invalid bitLength value - $bitLength');
    }
    double parts = bitLength / 8;
    for (var i = 0; i < parts.toInt(); ++i) {
      builder.addByte(nextInt(256));
    }
    Uint8List bytes = builder.toBytes();
    return bytes.toBigInt();
  }
}

//not in use yet
extension Uint8ListExtension on Uint8List {
  BigInt toBigInt() {
    BigInt result = BigInt.zero;

    for (final byte in this) {
      // reading in big-endian, so we essentially concat the new byte to the end
      result = (result << 8) | BigInt.from(byte);
    }
    return result;
  }
}

class DHpkcs3EngineError implements Exception {
  final String message;
  DHpkcs3EngineError(this.message);
  @override
  String toString() => message;
}

class DhParameterSpec {
  static const int defaultPrivateKeyLength = 256;

  final BigInt _p;
  final BigInt _g;
  final int _length;

  DhParameterSpec({
    required BigInt p,
    required BigInt g,
    int length = defaultPrivateKeyLength,
  })  : _p = p,
        _g = g,
        _length = length;

  /// Returns the size in bits of the random exponent (private value)
  int get length => _length;

  /// Returns the base generator g
  BigInt get g => _g;

  /// Returns the prime modulus p
  BigInt get p => _p;

  @override
  String toString() {
    return "DhParameterSpec; p: ${Utils.bigIntToUint8List(bigInt:p)}, g: ${Utils.bigIntToUint8List(bigInt:g)}, length: $length";
  }
}

class DhKeyPair {
  final BigInt _publicKey;
  final BigInt _privateKey;

  DhKeyPair({
    required BigInt publicKey,
    required BigInt privateKey,
  })  : _publicKey = publicKey,
        _privateKey = privateKey;

  BigInt get privateKey => _privateKey;

  BigInt get publicKey => _publicKey;

  @override
  String toString() {
    return "DhKeyPair; PublicKey: ${Utils.bigIntToUint8List(bigInt:publicKey)} ";
  }
  // be careful with this method, it is only for debugging purposes!!!
  String toStringAlsoPrivate() {
    return "DhKeyPair; PublicKey: ${Utils.bigIntToUint8List(bigInt:publicKey)}, "
        "PrivateKey: ${Utils.bigIntToUint8List(bigInt:privateKey)}";
  }
}


class DHpkcs3Engine {
  static final _log = Logger("ECDHPaceCurve");

  final DhParameterSpec _parameterSpec;

  late final BigInt _publicKey;
  late final BigInt _privateKey;
  late final BigInt _secretKey;

  /// Diffie-Hellman parameters used by this engine
  DhParameterSpec get parameterSpec => _parameterSpec;

  /// Must call generateKeyPair() method before accessing this value
  BigInt get publicKey => _publicKey;

  /// Must call generateKeyPair() method before accessing this value
  BigInt get privateKey => _privateKey;

  // Must call computeSecretKey() method before accessing this value
  BigInt get secretKey => _secretKey;


  factory DHpkcs3Engine.fromPrivate({required BigInt private,
                                    required DhParameterSpec parameterSpec}) {

    return DHpkcs3Engine(parameterSpec: parameterSpec, privateKey: private);
  }

  /// Construct an engine with the desired [DhParameterSpec]. If [privateKey] is
  /// provided, the key pair is created with the provided [privateKey],
  /// otherwise a new key pair is generated.
  DHpkcs3Engine({required DhParameterSpec parameterSpec, BigInt? privateKey, int? seed = null}) :
        _parameterSpec = parameterSpec{
    _log.debug("Creating DH engine with parameterSpec: ${parameterSpec}");
    if (privateKey != null)
      createKeyPair(privateKey: privateKey);
    else
      generateKeyPair(seed: seed);

    _log.sdVerbose("DHpkcs3Engine; Created DH engine;"
        "publicKey: ${Utils.bigIntToUint8List(bigInt:publicKey)}, "
        "privateKey: ${Utils.bigIntToUint8List(bigInt:_privateKey)}");
  }

  /// Compute the secret key using the other party public key
  BigInt computeSecretKey({required BigInt otherPublicKey}) {
    return otherPublicKey.modPow(
      _privateKey,
      _parameterSpec.p,
    );
  }

  /// Compute the secret key using the other party public key
  BigInt computeGenerator({required BigInt otherPublicKey, required BigInt nonce}) {
    _log.debug("DHpkcs3Engine.computeGenerator; otherPublicKey: ${Utils.bigIntToUint8List(bigInt:otherPublicKey)}");
    _log.sdVerbose("DHpkcs3Engine.computeGenerator; otherPublicKey: ${Utils.bigIntToUint8List(bigInt:otherPublicKey)}, "
        "nonce: ${Utils.bigIntToUint8List(bigInt:nonce)}");
    //Gephemeral = (pow(g, s, p) * H) % p
    //(g.modPow(nonce, p) * H ) % p

    BigInt H = this.computeSecretKey(otherPublicKey: otherPublicKey);
    BigInt generator = (_parameterSpec.g.modPow(nonce, _parameterSpec.p) * H) % _parameterSpec.p;

    return generator;
  }

  DhKeyPair createKeyPair({required BigInt privateKey}) {
    _log.verbose("DHpkcs3Engine; Creating key pair...");
    _privateKey = privateKey;
    _publicKey = generatePublicKey(privateKey: privateKey);
    return DhKeyPair(
      publicKey: _publicKey,
      privateKey: _privateKey,
    );
  }

  /// Generate [publicKey] and [privateKey] based on the [parameterSpec] of this engine
  DhKeyPair generateKeyPair({int? seed = null}) {
    _log.verbose("DHpkcs3Engine; Generating key pair...");
    _privateKey = generatePrivateKey(seed: seed);
    _publicKey = generatePublicKey(privateKey: privateKey);
    return DhKeyPair(
      publicKey: _publicKey,
      privateKey: _privateKey,
    );
  }

  @protected
  BigInt generatePrivateKey({int? seed = null}) {
    _log.debug("DHpkcs3Engine.generatePrivateKey. Is seed set?: ${seed != null}");
    Random rnd;
    try {
      if (seed != null)
        rnd = Random(seed);
      else
        rnd = Random.secure();
    } on UnsupportedError {
      throw DHpkcs3EngineError(
          'This platform cannot provide a cryptographically secure source of random numbers');
    }

    BigInt lowerBound = BigInt.two.pow(parameterSpec.length - 1);
    late BigInt generated;

    bool loopCondition = true;
    while (loopCondition) {
      generated = rnd.nextBigInt(parameterSpec.length);
      if (generated.compareTo(lowerBound) >= 0 &&
          generated.compareTo(BigInt.two * lowerBound) < 0) {
        loopCondition = false;
      }
    }
    return generated;
  }

  @protected
  BigInt generatePublicKey({required BigInt privateKey}) {
    _log.verbose("DHpkcs3Engine.generatePublicKey");
    return
      _parameterSpec.g.modPow(
      privateKey,
      _parameterSpec.p,
    );
  }
}

