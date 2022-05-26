// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/extensions.dart';

enum AAPublicKeyType {
  // ignore: constant_identifier_names
  RSA,
  // ignore: constant_identifier_names
  ECC
}

// Represents Active Authentication Public Key Info
class AAPublicKey {

  final Uint8List _encPubKey;
  AAPublicKeyType _type = AAPublicKeyType.ECC;
  late Uint8List _subPubKeyBytes;

  Uint8List rawSubjectPublicKey() {
    return _subPubKeyBytes;
  }

  Uint8List toBytes() {
    return _encPubKey;
  }

  AAPublicKeyType get type => _type;

  AAPublicKey.fromBytes(final Uint8List encPubKey) : _encPubKey = encPubKey {
    // Parse key type and SubjectPublicKey bytes

    final tvPubKeyInfo = TLV.decode(encPubKey);
    if(tvPubKeyInfo.tag.value != 0x30) { // Sequence
      EfParseError(
        "Invalid SubjectPublicKeyInfo tag=${tvPubKeyInfo.tag.value.hex()}, expected tag=30"
      );
    }

    final tvAlg = TLV.decode(tvPubKeyInfo.value);
    if(tvAlg.tag.value != 0x30) { // Sequence
      EfParseError(
        "Invalid AlgorithmIdentifier tag=${tvAlg.tag.value.hex()}, expected tag=30"
      );
    }

    final tvAlgOID = TLV.decode(tvAlg.value);
    if(tvAlg.tag.value != 0x06) { // OID
      EfParseError(
        "Invalid Algorithm OID object tag=${tvAlgOID.tag.value.hex()}, expected tag=06"
      );
    }

    final rsaOID = "2A864886F70D010101".parseHex();
    if(ListEquality().equals(tvAlgOID.value, rsaOID)) {
      _type = AAPublicKeyType.RSA;
    }

    _subPubKeyBytes = tvPubKeyInfo.value.sublist(tvAlg.encodedLen);
    if(_subPubKeyBytes[0] != 0x03) { // Bit String
      EfParseError(
        "Invalid SubjectPublicKey object tag=${_subPubKeyBytes[0].hex()}, expected tag=03"
      );
    }
  }
}