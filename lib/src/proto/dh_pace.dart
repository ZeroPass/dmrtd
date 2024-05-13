//  Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.


import "dart:typed_data";

import "package:dmrtd/src/proto/public_key_pace.dart";
import "package:dmrtd/src/utils.dart";
import "package:dmrtd/src/extension/logging_apis.dart";
import 'package:pointycastle/export.dart';
import "package:logging/logging.dart";
import "package:pointycastle/ecc/api.dart";

import "package:dmrtd/src/crypto/diffie_hellman.dart";

import "domain_parameter.dart";

/*
*
*   RFC 5114
*   (https://datatracker.ietf.org/doc/html/rfc5114)
*
ID - Name                 Size(bit) Type Reference
0  - 1024-bit MODP with   160-bit   1024/160
1  - 2048-bit MODP with   224-bit   2048/224
2  - 2048-bit MODP with   256-bit   2048/256
*
* */

DhParameterSpec RFC5114_1024_MODP_160 = DhParameterSpec(
    p: BigInt.parse("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
        "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
        "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
        "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
        "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
        "DF1FB2BC2E4A4371", radix: 16),
    g: BigInt.parse("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
        "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
        "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
        "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
        "855E6EEB22B3B2E5", radix: 16),
    length: 160);


DhParameterSpec RFC5114_2048_MODP_224 = DhParameterSpec(
    p: BigInt.parse("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1"
        "B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15"
        "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212"
        "9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207"
        "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708"
        "B3BF8A317091883681286130BC8985DB1602E714415D9330"
        "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D"
        "CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8"
        "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763"
        "C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71"
        "CF9DE5384E71B81C0AC4DFFE0C10E64F", radix: 16),
    g: BigInt.parse("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF"
        "74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA"
        "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7"
        "C17669101999024AF4D027275AC1348BB8A762D0521BC98A"
        "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE"
        "F180EB34118E98D119529A45D6F834566E3025E316A330EF"
        "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB"
        "10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381"
        "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269"
        "EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179"
        "81BC087F2A7065B384B890D3191F2BFA", radix: 16),
    length: 224);

DhParameterSpec RFC5114_2048_MODP_256 = DhParameterSpec(
    p: BigInt.parse("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F2"
        "5D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30"
        "16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD"
        "5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B"
        "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C"
        "4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E"
        "F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D9"
        "67E144E5140564251CCACB83E6B486F6B3CA3F7971506026"
        "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C3"
        "75F26375D7014103A4B54330C198AF126116D2276E11715F"
        "693877FAD7EF09CADB094AE91E1A1597", radix: 16),
    g: BigInt.parse("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF2054"
        "07F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555"
        "BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18"
        "A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B"
        "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC83"
        "1D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55"
        "A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14"
        "C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915"
        "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6"
        "184B523D1DB246C32F63078490F00EF8D647D148D4795451"
        "5E2327CFEF98C582664B4C0F6CC41659", radix: 16),
    length: 256);




class DHPaceError implements Exception {
  final String message;
  DHPaceError(this.message);
  @override
  String toString() => message;
}

class DHBasicAgreementPACEError implements Exception {
  final String message;
  DHBasicAgreementPACEError(this.message);
  @override
  String toString() => message;
}

class DHBasicAgreementPACE extends ECDHBasicAgreement{
  //ECPoint calculateAgreementAndReturnPoint(ECPublicKey pubKey) {}
}

class DHPace {
  static final _log = Logger("DHPaceCurve");
  late DomainParameter selectedDomainParameter; //only for logging purposes

  DHpkcs3Engine? _engine;
  DHpkcs3Engine? _engineEphemeral;
  DhParameterSpec _domainParameters; //only for override(testing) purposes


  bool get isPublicKeySet => _engine != null;
  BigInt get publicKey => _engine!.publicKey;

  bool get isEphemeralPublicKeySet => _engineEphemeral != null;
  BigInt get ephemeralPublicKey => _engineEphemeral!.publicKey;

  DHPace({required int id, required DhParameterSpec domainParameters})
      : _domainParameters = domainParameters
  {
    if (!ICAO_DOMAIN_PARAMETERS.containsKey(id)) {
      _log.error("DHPace; Domain parameter with id $id does not exist.");
      throw DHPaceError("DHPace; Domain parameter with id $id does not exist.");
    }

    selectedDomainParameter = ICAO_DOMAIN_PARAMETERS[id]!;
    _log.fine(selectedDomainParameter.toString());
    //creating engine (private and public key will be generated with random seed)
    _engine = DHpkcs3Engine(parameterSpec: domainParameters);

  }

  String toStringWithCaution(){
    _log.warning("This function is only for testing purposes. It prints private keys. Do not use in production.");
    String forReturn = "DHPace: ${selectedDomainParameter.name}: ";
    bool isAny = false;
    if (isPublicKeySet && _engine!.privateKey != null){
      forReturn += " private key: ${_engine!.privateKey.toString()}";
      isAny = true;
    }
    if (isEphemeralPublicKeySet && _engine!.privateKey != null){
      forReturn += " ephemeral private key: ${_engineEphemeral!.privateKey.toString()}";
      isAny = true;
    }
    if (!isAny){
      forReturn += " <no private keys>";
    }
    return forReturn;
  }

  void generateKeyPairFromPriv({required Uint8List privKey}){
    _log.fine("DHPace.generateKeyPairFromPriv; Generating key pair for domain parameter ${selectedDomainParameter.name}.");
    _log.sdVerbose("DHPace.generateKeyPairFromPriv; PrivateKey: ${privKey.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}");

    //override engine with predefined private key
    _engine = DHpkcs3Engine.fromPrivate(private: Utils.uint8ListToBigInt(privKey), parameterSpec: _domainParameters);

    if (!isPublicKeySet) {
      _log.error("DHPace.generateKeyPairFromPriv; Public key is null. Generate key pair first.");
      throw DHPaceError("DHPace.generateKeyPairFromPriv; Private key is null. Generate key pair first.");
    }

    _log.debug("DHPace.generateKeyPairFromPriv; Generated public key: $publicKey");
  }

  BigInt transformPublic({required PublicKeyPACEdH pubKey}){
    // this function is used for converting received public key (from ICC) to BigInt
    _log.fine("Generating key pair (from PublicKeyPACEdH) for domain parameter ${selectedDomainParameter.name}.");
    return Utils.uint8ListToBigInt(pubKey.toRelavantBytes());
  }

  void generateKeyPair({int? seed = null}){
    _log.fine("DHPace.generateKeyPair; Generating key pair for domain parameter ${selectedDomainParameter.name}.");

    DhKeyPair keyPair = _engine!.generateKeyPair(seed: seed);
    _log.debug("DHPace.generateKeyPair; Generated public key: ${keyPair.toString()}");
    _log.sdVerbose("DHPace.generateKeyPair; Generated public/private key: ${keyPair.toStringAlsoPrivate()}");
  }

  void generateKeyPairWithCustomGenerator({required BigInt ephemeralGenerator,
  int? seed = null}) {
    _log.fine("DHPace.generateKeyPairWithCustomGenerator; Generating custom key pair for domain parameter "
            "${selectedDomainParameter.name}.");

    DhParameterSpec domainParametersEphemeral =
      DhParameterSpec(p: _domainParameters.p,
                      g: ephemeralGenerator,
                 length: _domainParameters.length);

    _engineEphemeral = DHpkcs3Engine(parameterSpec: domainParametersEphemeral, seed: seed);

    if (!isEphemeralPublicKeySet) {
      _log.error("DHPace.generateKeyPairWithCustomGenerator; Public key is null. Generate key pair first.");
      throw DHPaceError("DHPace.generateKeyPairWithCustomGenerator; Private key is null. Generate key pair first.");
    }

    _log.debug("Generated public key: $ephemeralPublicKey");
  }

  void setEphemeralKeyPair({required Uint8List private, required BigInt ephemeralGenerator}){
    _log.fine("DHPace.setEphemeralKeyPair; Setting ephemeral key pair for domain parameter ${selectedDomainParameter.name}.");
    _log.debug("DHPace.setEphemeralKeyPair; This function is only for testing purposes. Do not use in production.");

    DhParameterSpec domainParametersEphemeral =
    DhParameterSpec(p: _domainParameters.p,
        g: ephemeralGenerator,
        length: _domainParameters.length);

    _engineEphemeral = DHpkcs3Engine(parameterSpec: domainParametersEphemeral,
                                     privateKey: Utils.uint8ListToBigInt(private));

    if (!isEphemeralPublicKeySet) {
      _log.error("DHPace.setEphemeralKeyPair; Ephemeral public key is null. Generate key pair first.");
      throw DHPaceError("DHPace.setEphemeralKeyPair; Ephemeral public key is null. Generate key pair first.");
    }

    _log.debug("DHPace.setEphemeralKeyPair; Generated public key: ${ephemeralPublicKey}");
    _log.sdVerbose("DHPace.setEphemeralKeyPair; Generated public/private key: ${ephemeralPublicKey}");
  }

  PublicKeyPACEdH getPubKey(){
    if (!isPublicKeySet) {
      _log.error("DHPace.getPubKey; Public key is null. Generate key pair first.");
      throw DHPaceError("DHPace.getPubKey; Private key is null. Generate key pair first.");
    }
    return PublicKeyPACEdH(pub:Utils.bigIntToUint8List(bigInt: publicKey));
  }

  PublicKeyPACEdH getPubKeyEphemeral(){
    if (!isEphemeralPublicKeySet) {
      _log.error("DHPace.getPubKeyEphemeral; Public ephemeral key is null. Generate key pair first.");
      throw DHPaceError("DHPace.getPubKeyEphemeral; Public ephemeral key is null. Generate ephemeral key pair first.");
    }
    return PublicKeyPACEdH(pub:Utils.bigIntToUint8List(bigInt: ephemeralPublicKey));
  }

  BigInt getSharedSecret({required Uint8List otherPubKey}){
    _log.fine("DHPace.getSharedSecret;Calculate shared secret with domain parameter ${selectedDomainParameter.name}.");
    if (!isPublicKeySet) {
      _log.error("DHPace.getSharedSecret; Private/public key is null. Generate key pair first.");
      throw DHPaceError("DHPace.getSharedSecret; Private/public key is null. Generate key pair first.");
    }
    if (_engine == null ) {
      _log.error("DHPace.getSharedSecret; Engine is null. Generate key pair first.");
      throw DHPaceError("DHPace.getSharedSecret; Engine is null. Generate key pair first.");
    }

    return _engine!.computeSecretKey(otherPublicKey: Utils.uint8ListToBigInt(otherPubKey));
  }

  BigInt getEphemeralSharedSecret({required Uint8List otherEphemeralPubKey}){
    _log.fine("Calculate ephemeral shared secret with domain parameter ${selectedDomainParameter.name}.");
    if (!isEphemeralPublicKeySet) {
      _log.error("DHPace.getEphemeralSharedSecret; Ephemeral private key is null. Generate key pair first.");
      throw DHPaceError("DHPace.getEphemeralSharedSecret; Ephemeral private key is null. Generate key pair first.");
    }
    if (_engineEphemeral == null ) {
      _log.error("DHPace.getEphemeralSharedSecret; Ephemeral engine is null. Generate key pair first.");
      throw DHPaceError("DHPace.getEphemeralSharedSecret; Ephemeral engine is null. Generate key pair first.");
    }

    return _engineEphemeral!.computeSecretKey(
        otherPublicKey: Utils.uint8ListToBigInt(otherEphemeralPubKey));
  }

  Uint8List getMappedGenerator({required Uint8List otherPubKey, required Uint8List nonce}) {
    _log.fine("Calculating mapped generator with domain parameter ${selectedDomainParameter.name}.");
    // Specified in section 4.3.3.3.1 - DH of ICAO 9303 p11
    // G` = G^s * H
    // s = nonce
    // G = predefined generator point
    // H = shared secret (my private key * other public key)

    if (!isPublicKeySet) {
      _log.error("DHPace.getMappedGenerator; Public key is null. Generate key pair first.");
      throw DHPaceError("DHPace.getMappedGenerator; Private key is null. Generate key pair first.");
    }

    if (_engine == null ) {
      _log.error("DHPace.getMappedGenerator; Engine is null. Generate key pair first.");
      throw DHPaceError("DHPace.getMappedGenerator; Engine is null. Generate key pair first.");
    }

    BigInt generator = _engine!.computeGenerator(
        otherPublicKey: Utils.uint8ListToBigInt(otherPubKey),
        nonce: Utils.uint8ListToBigInt(nonce));
    return Utils.bigIntToUint8List(bigInt: generator);
  }
}


class DHPaceCurve0 extends DHPace {
  DHPaceCurve0()
      : super(id: 0, domainParameters: RFC5114_1024_MODP_160);
}

class DHPaceCurve1 extends DHPace {
  DHPaceCurve1()
      : super(id: 1, domainParameters: RFC5114_2048_MODP_224);
}

class DHPaceCurve2 extends DHPace {
  DHPaceCurve2()
      : super(id: 2, domainParameters: RFC5114_2048_MODP_256);
}

class DomainParameterSelectorDH{
  static final _log = Logger("DomainParameterSelectorDH");

  static DHPace getDomainParameter({required int id}) {
    if (!ICAO_DOMAIN_PARAMETERS.containsKey(id)) {
      _log.error("Domain parameter (DH) with id $id does not exist.");
      throw DHPaceError("Domain parameter with id $id does not exist.");
    }
    switch (id) {
      case 0:
        _log.finer("Selected domain parameter: 1024-bit MODP with 160-bit prime order subgroup");
        return DHPaceCurve0();
      case 1:
        _log.finer("Selected domain parameter: 2048-bit MODP with 224-bit prime order subgroup");
        return DHPaceCurve1();
      case 2:
        _log.finer("Selected domain parameter: 2048-bit MODP with 256-bit prime order subgroup");
        return DHPaceCurve2();

        default:
        _log.error("Domain parameter with id $id is not supported.");
        throw DHPaceError("Domain parameter with id $id is not supported.");
    }
  }
}