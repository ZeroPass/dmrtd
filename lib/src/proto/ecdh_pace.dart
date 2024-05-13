//  Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.

import "dart:typed_data";

import "package:dmrtd/extensions.dart";
import "package:dmrtd/src/crypto/crypto_utils.dart";
import "package:dmrtd/src/proto/public_key_pace.dart";
import "package:dmrtd/src/utils.dart";
import "package:dmrtd/src/extension/logging_apis.dart";
import 'package:pointycastle/export.dart';
import "package:logging/logging.dart";
import "package:pointycastle/api.dart";
import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/ecc/curves/secp256r1.dart";

import "domain_parameter.dart";


class ECDHPaceError implements Exception {
  final String message;
  ECDHPaceError(this.message);
  @override
  String toString() => message;
}

class ECDHBasicAgreementPACEError implements Exception {
  final String message;
  ECDHBasicAgreementPACEError(this.message);
  @override
  String toString() => message;
}

class ECDHBasicAgreementPACE extends ECDHBasicAgreement{
  ECPoint calculateAgreementAndReturnPoint(ECPublicKey pubKey) {
    var params = key.parameters;
    if (pubKey.parameters?.curve != params?.curve) {
      throw ECDHBasicAgreementPACEError('ECDH public key has wrong domain parameters');
    }

    var d = key.d!;

    // Always perform calculations on the exact curve specified by our private key's parameters
    var Q = cleanPoint(params!.curve, pubKey.Q!);
    if (Q == null || Q.isInfinity) {
      throw ECDHBasicAgreementPACEError('Infinity is not a valid public key for ECDH');
    }

    var h = (params as ECDomainParametersImpl).h!;

    if (!(h.compareTo(BigInt.one) == 0)) {
      d = (h.modInverse(params.n) * d) % params.n;
      Q = Q * h;
    }

    var P = (Q! * d)!;

    if (P.isInfinity) {
      throw ECDHBasicAgreementPACEError(
          'Infinity is not a valid agreement value for ECDH');
    }

    return P;
  }
}

class ECDHPace {
  static final _log = Logger("ECDHPaceCurve");
  late DomainParameter selectedDomainParameter;

  ECDomainParameters domainParameters;
  // first keypair
  ECPrivateKey? _priv;
  ECPublicKey? _pub;

  // generated keypair
  ECPrivateKey? _privEphemeral;
  ECPublicKey? _pubEphemeral;

  bool get isPublicKeySet => _pub != null;
  ECPublicKey get publicKey => _pub!;

  bool get isEphemeralPublicKeySet => _pubEphemeral != null;
  ECPublicKey get ephemeralPublicKey => _pubEphemeral!;

  ECDHPace({required int id, required ECDomainParameters domainParameters})
                :domainParameters = domainParameters
  {
    if (!ICAO_DOMAIN_PARAMETERS.containsKey(id)) {
      _log.error("Domain parameter with id $id does not exist.");
      throw Exception("Domain parameter with id $id does not exist.");
    }

    selectedDomainParameter = ICAO_DOMAIN_PARAMETERS[id]!;
    _log.fine(selectedDomainParameter.toString());
  }

  String toStringWithCaution(){
    _log.warning("This function is only for testing purposes. It prints private keys. Do not use in production.");
    String forReturn = "ECDHPaceCurve: ${selectedDomainParameter.name}: ";
    bool isAny = false;
    if (_priv != null && _priv!.d != null){
      forReturn += " private key: ${Utils.bigIntToUint8List(bigInt: _priv!.d!).hex()}";
      isAny = true;
    }
    if (_privEphemeral != null && _privEphemeral!.d != null){
      forReturn += " ephemeral private key: ${Utils.bigIntToUint8List(bigInt: _privEphemeral!.d!).hex()}";
      isAny = true;
    }
    if (!isAny){
      forReturn += " <no private keys>";
    }
    return forReturn;
  }

  static PublicKeyPACEeCDH ecPointToList({required ECPoint point}) {
    BigInt? x = point.x!.toBigInteger();
    BigInt? y = point.y!.toBigInteger();

    if (x == null || y == null) {
      _log.error(
          "Public key has no parameters (as BigInteger). Something went wrong in PC library.");
      throw ECDHPaceError(
          "Public key has no parameters(as BigInteger). Something went wrong in PC library.");
    }
    return PublicKeyPACEeCDH(x: x, y: y);
  }

  void generateKeyPairFromPriv({required Uint8List privKey}){
    _log.fine("Generating key pair for domain parameter ${selectedDomainParameter.name}.");
    var privateKeyBigInt = BigInt.parse(privKey.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(), radix: 16);

    // Create the private key
    _priv = ECPrivateKey(privateKeyBigInt, domainParameters);
    _pub = ECPublicKey(domainParameters.G * _priv!.d, domainParameters);
  }

  ECPublicKey transformPublic({required PublicKeyPACEeCDH pubKey}){
    // this function is used for converting received public key (from ICC) to ECPublicKey
    _log.fine("Generating key pair (from PublicKeyPACEeCDH) for domain parameter ${selectedDomainParameter.name}.");
    _log.sdDebug("Received public key: ${pubKey.toString()}");
    ECPoint ecPoint = domainParameters.curve.createPoint(pubKey.x, pubKey.y);
    return ECPublicKey(ecPoint, domainParameters);
  }

  ECPoint get G => domainParameters.G;

  void generateKeyPair({Uint8List? seed32byte = null}){
    _log.fine("Generating key pair for domain parameter ${selectedDomainParameter.name}.");
    if (seed32byte == null){
      _log.debug("Seed is null. Generating random seed (32 bytes).");
      seed32byte = randomBytes(32);
    }
    if (seed32byte.length != 32){
      _log.error("Seed must be 256 bits long.");
      throw ECDHPaceError("Seed must be 256 bits long.");
    }

    var secureRandom = SecureRandom("Fortuna")..seed(KeyParameter(seed32byte));
    _log.debug("Seed is calculated. Generating key pair (Generator - EC) ...");

    var generator = KeyGenerator('EC')
      ..init(ParametersWithRandom(
          ECKeyGeneratorParameters(domainParameters),
          secureRandom));
    var keyPair = generator.generateKeyPair();
    _priv = keyPair.privateKey as ECPrivateKey;
    _pub = keyPair.publicKey as ECPublicKey;
    _log.sdDebug("Generated public key: ${ecPointToList(point: _pub!.Q!).toString()}");
    _log.sdShout("Generated private key: ${Utils.bigIntToUint8List(bigInt: _priv!.d!).hex()}");
  }

  void generateKeyPairWithCustomGenerator({required ECPoint mappedGenerator,
    Uint8List? seed32byte = null}) {
    _log.fine(
        "Generating custom key pair for domain parameter "
            "${selectedDomainParameter.name}.");
    if (seed32byte == null) {
      _log.debug("Seed is null. Generating random seed (32 bytes).");
      seed32byte = randomBytes(32);
    }
    if (seed32byte.length != 32) {
      _log.error("Seed must be 256 bits long.");
      throw ECDHPaceError("Seed must be 256 bits long.");
    }

    _log.sdVerbose("Mapped generator: ${ecPointToList(point: mappedGenerator).toString()}");

    var secureRandom = SecureRandom("Fortuna")..seed(KeyParameter(seed32byte));
    _log.debug("Seed is calculated. Generating key pair (Generator - EC) ...");

    ECDomainParametersImpl domainParametersCustom =
          ECDomainParametersImpl(domainParameters.domainName,
                                  this.domainParameters.curve,
                                  mappedGenerator,
                                  domainParameters.n);

    var generator = KeyGenerator('EC')
      ..init(ParametersWithRandom(
          ECKeyGeneratorParameters(domainParametersCustom),
          secureRandom));

    AsymmetricKeyPair keyPair = generator.generateKeyPair();

    _privEphemeral = keyPair.privateKey as ECPrivateKey;
    _pubEphemeral = keyPair.publicKey as ECPublicKey;

    if (_privEphemeral!.d == null){
      _log.error("Ephemeral private key is null. Something went wrong in PC library.");
      throw ECDHPaceError("Ephemeral private key is null. Something went wrong in PC library.");
    }

    _log.sdDebug("Ephemeral public key: ${ecPointToList(point: _pubEphemeral!.Q!).toString()}");
    _log.sdVerbose("Ephemeral private key(x): ${Utils.bigIntToUint8List(bigInt:_privEphemeral!.d!).hex()}");
  }

  void setEphemeralKeyPair({required Uint8List private, required ECPoint mappedGenerator}){
    _log.fine("Setting ephemeral key pair for domain parameter ${selectedDomainParameter.name}.");
    _log.debug("This function is only for testing purposes. Do not use in production.");

    BigInt privateKeyBigInt = BigInt.parse(private.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(), radix: 16);

    ECDomainParametersImpl domainParametersCustom =
              ECDomainParametersImpl(domainParameters.domainName,
                                      domainParameters.curve,
                                      mappedGenerator,
                                      domainParameters.n);

    // Create the private key
    _privEphemeral = ECPrivateKey(privateKeyBigInt, domainParametersCustom);
    _pubEphemeral = ECPublicKey(domainParametersCustom.G * _privEphemeral!.d, domainParametersCustom);
  }

  PublicKeyPACEeCDH getPubKey(){
    if (_pub == null) {
      _log.error("Public key is null. Generate key pair first.");
      throw ECDHPaceError("Private key is null. Generate key pair first.");
    }
    if (_pub!.Q == null || _pub!.Q!.x == null || _pub!.Q!.y == null){
      _log.error("Public key has no parameters. Something went wrong in PC library.");
      throw ECDHPaceError("Public key has no parameters. Something went wrong in PC library.");
    }
    var x = _pub!.Q!.x!.toBigInteger();
    var y = _pub!.Q!.y!.toBigInteger();

    if (x == null  || y == null){
      _log.error("Public key has no parameters (as BigInteger). Something went wrong in PC library.");
      throw ECDHPaceError("Public key has no parameters(as BigInteger). Something went wrong in PC library.");
    }
    return PublicKeyPACEeCDH(x:x, y:y);
  }

  PublicKeyPACEeCDH getPubKeyEphemeral(){
    if (_pubEphemeral == null) {
      _log.error("Public ephemeral key is null. Generate key pair first.");
      throw ECDHPaceError("Public ephemeral key is null. Generate ephemeral key pair first.");
    }
    if (_pubEphemeral!.Q == null || _pubEphemeral!.Q!.x == null || _pubEphemeral!.Q!.y == null){
      _log.error("Public ephemeral key has no parameters. Something went wrong in PC library.");
      throw ECDHPaceError("Public ephemeral key has no parameters. Something went wrong in PC library.");
    }
    var x = _pubEphemeral!.Q!.x!.toBigInteger();
    var y = _pubEphemeral!.Q!.y!.toBigInteger();

    if (x == null  || y == null){
      _log.error("Public ephemeral key has no parameters (as BigInteger). Something went wrong in PC library.");
      throw ECDHPaceError("Public ephemeral key has no parameters(as BigInteger). Something went wrong in PC library.");
    }
    return PublicKeyPACEeCDH(x:x, y:y);
  }

  ECPoint getSharedSecret({required ECPublicKey otherPubKey}){
    _log.fine("Calculate shared secret with domain parameter ${selectedDomainParameter.name}.");
    if (_priv == null) {
      _log.error("Private key is null. Generate key pair first.");
      throw ECDHPaceError("Private key is null. Generate key pair first.");
    }

    ECDHBasicAgreementPACE keyAgreement = ECDHBasicAgreementPACE()..init(_priv!);
    return keyAgreement.calculateAgreementAndReturnPoint(otherPubKey);
  }

  ECPoint getEphemeralSharedSecret({required ECPublicKey otherEphemeralPubKey}){
    _log.fine("Calculate ephemeral shared secret with domain parameter ${selectedDomainParameter.name}.");
    if (_privEphemeral == null) {
      _log.error("Ephemeral private key is null. Generate key pair first.");
      throw ECDHPaceError("Ephemeral private key is null. Generate key pair first.");
    }

    ECDHBasicAgreementPACE keyAgreement = ECDHBasicAgreementPACE()..init(_privEphemeral!);
    return keyAgreement.calculateAgreementAndReturnPoint(otherEphemeralPubKey);
  }

  ECPoint getMappedGenerator({required ECPublicKey otherPubKey, required Uint8List nonce}) {
    _log.fine("Calculating mapped generator with domain parameter ${selectedDomainParameter.name}.");
    // Specified in section 4.3.3.3.1 - ECDH of ICAO 9303 p11
    // G` = s x G + H
    // s = nonce
    // G = predefined generator point
    // H = shared secret (my private key * other public key)

    if (_priv == null) {
      _log.error("Private key is null. Generate key pair first.");
      throw ECDHPaceError("Private key is null. Generate key pair first.");
    }

    ECPoint sharedSecret = getSharedSecret(otherPubKey: otherPubKey);
    _log.sdVerbose("Shared secret in mapped generator (X, Y): "
        "${ECDHPace.ecPointToList(point: sharedSecret).toBytes()}");

    ECPoint? pointG = _priv!.parameters?.G;
    if (pointG == null) {
      _log.error("ECDHPaceCurve.getMappedGeneratorPoint; G is null. Something went wrong in PC library.");
      throw ECDHPaceError("ECDHPaceCurve.getMappedGeneratorPoint; Point G is null. Something went wrong in PC library.");
    }

    BigInt nonceBigInt = Utils.uint8ListToBigInt(nonce);

    ECPoint? p = pointG! * nonceBigInt;
    if (p == null) {
      _log.error("ECDHPaceCurve.getMappedGeneratorPoint; p is null. Something went wrong in PC library.");
      throw ECDHPaceError("ECDHPaceCurve.getMappedGeneratorPoint; p is null. Something went wrong in PC library.");
    }

    ECPoint? mappedGenerator = p! + sharedSecret;
    if (mappedGenerator == null) {
      _log.error("ECDHPaceCurve.getMappedGeneratorPoint; mappedGenerator is null. Something went wrong in PC library.");
      throw ECDHPaceError("ECDHPaceCurve.getMappedGeneratorPoint; mappedGenerator is null. Something went wrong in PC library.");
    }
    return mappedGenerator!;
  }
}


class ECDHPaceCurve8 extends ECDHPace {
  ECDHPaceCurve8()
      : super(id: 8, domainParameters: ECCurve_secp192r1());
}
class ECDHPaceCurve9 extends ECDHPace {
  ECDHPaceCurve9()
      : super(id: 9, domainParameters: ECCurve_brainpoolp192r1());
}
class ECDHPaceCurve10 extends ECDHPace {
  ECDHPaceCurve10()
      : super(id: 10, domainParameters: ECCurve_secp224r1());
}
class ECDHPaceCurve11 extends ECDHPace {
  ECDHPaceCurve11()
      : super(id: 11, domainParameters: ECCurve_brainpoolp224r1());
}
class ECDHPaceCurve12 extends ECDHPace {
  ECDHPaceCurve12()
      : super(id: 12, domainParameters: ECCurve_secp256r1());
}
class ECDHPaceCurve13 extends ECDHPace {
  ECDHPaceCurve13()
      : super(id: 13, domainParameters: ECCurve_brainpoolp256r1());
}
class ECDHPaceCurve14 extends ECDHPace {
  ECDHPaceCurve14()
      : super(id: 14, domainParameters: ECCurve_brainpoolp320r1());
}
class ECDHPaceCurve15 extends ECDHPace {
  ECDHPaceCurve15()
      : super(id: 15, domainParameters: ECCurve_secp384r1());
}
class ECDHPaceCurve16 extends ECDHPace {
  ECDHPaceCurve16()
      : super(id: 16, domainParameters: ECCurve_brainpoolp384r1());
}
class ECDHPaceCurve17 extends ECDHPace {
  ECDHPaceCurve17()
      : super(id: 17, domainParameters: ECCurve_brainpoolp512r1());
}
class ECDHPaceCurve18 extends ECDHPace {
  ECDHPaceCurve18()
      : super(id: 18, domainParameters: ECCurve_secp521r1());
}


class DomainParameterSelectorECDH{
  static final _log = Logger("DomainParameterSelectorECDH");

  static ECDHPace getDomainParameter({required int id}) {
    if (!ICAO_DOMAIN_PARAMETERS.containsKey(id)) {
      _log.error("Domain parameter (ECDH) with id $id does not exist.");
      throw ECDHPaceError("Domain parameter with id $id does not exist.");
    }
    switch (id) {
      case 8:
        _log.finer("Selected domain parameter: NIST P-192 (secp192r1)");
        return ECDHPaceCurve8();
      case 9:
        _log.finer("Selected domain parameter: BrainpoolP192r1");
        return ECDHPaceCurve9();
      case 10:
        _log.finer("Selected domain parameter: NIST P-224 (secp224r1)");
        return ECDHPaceCurve10();
      case 11:
        _log.finer("Selected domain parameter: BrainpoolP224r1");
        return ECDHPaceCurve11();
      case 12:
        _log.finer("Selected domain parameter: NIST P-256 (secp256r1)");
        return ECDHPaceCurve12();
      case 13:
        _log.finer("Selected domain parameter: BrainpoolP256r1");
        return ECDHPaceCurve13();
      case 14:
        _log.finer("Selected domain parameter: BrainpoolP320r1");
        return ECDHPaceCurve14();
      case 15:
        _log.finer("Selected domain parameter: NIST P-384 (secp384r1)");
        return ECDHPaceCurve15();
      case 16:
        _log.finer("Selected domain parameter: BrainpoolP384r1");
        return ECDHPaceCurve16();
      case 17:
        _log.finer("Selected domain parameter: BrainpoolP512r1");
        return ECDHPaceCurve17();
      case 18:
        _log.finer("Selected domain parameter: NIST P-521 (secp521r1)");
        return ECDHPaceCurve18();
      default:
        _log.error("Domain parameter with id $id is not supported.");
        throw ECDHPaceError("Domain parameter with id $id is not supported.");
    }
  }
}