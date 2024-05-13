// Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.


import "package:dmrtd/src/extension/logging_apis.dart";
import 'package:logging/logging.dart';
import 'package:pointycastle/asn1/object_identifiers_database.dart';
import 'package:collection/collection.dart';


import '../types/exception.dart';

// here you can add additional object identifiers that are not defined in pointycastle library

/*
  ID_PACE_DH_GM_3DES_CBC_CBC,       0.4.0.127.0.7.2.2.4.1.1
  ID_PACE_DH_GM_AES_CBC_CMAC_128,   0.4.0.127.0.7.2.2.4.1.2
  ID_PACE_DH_GM_AES_CBC_CMAC_192,   0.4.0.127.0.7.2.2.4.1.3
  ID_PACE_DH_GM_AES_CBC_CMAC_256,   0.4.0.127.0.7.2.2.4.1.4
  ID_PACE_DH_IM_3DES_CBC_CBC,       0.4.0.127.0.7.2.2.4.3.1
  ID_PACE_DH_IM_AES_CBC_CMAC_128,   0.4.0.127.0.7.2.2.4.3.2
  ID_PACE_DH_IM_AES_CBC_CMAC_192,   0.4.0.127.0.7.2.2.4.3.3
  ID_PACE_DH_IM_AES_CBC_CMAC_256,   0.4.0.127.0.7.2.2.4.3.4
  ID_PACE_ECDH_GM_3DES_CBC_CBC,     0.4.0.127.0.7.2.2.4.2.1
  ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 0.4.0.127.0.7.2.2.4.2.2
  ID_PACE_ECDH_GM_AES_CBC_CMAC_192, 0.4.0.127.0.7.2.2.4.2.3
  ID_PACE_ECDH_GM_AES_CBC_CMAC_256, 0.4.0.127.0.7.2.2.4.2.4
  ID_PACE_ECDH_IM_3DES_CBC_CBC,     0.4.0.127.0.7.2.2.4.4.1
  ID_PACE_ECDH_IM_AES_CBC_CMAC_128, 0.4.0.127.0.7.2.2.4.4.2
  ID_PACE_ECDH_IM_AES_CBC_CMAC_192, 0.4.0.127.0.7.2.2.4.4.3
  ID_PACE_ECDH_IM_AES_CBC_CMAC_256, 0.4.0.127.0.7.2.2.4.4.4
  ID_PACE_ECDH_CAM_AES_CBC_CMAC_128, //not known UID
  ID_PACE_ECDH_CAM_AES_CBC_CMAC_192, //not known UID
  ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 //not known UID
 */

//PACEInfo.protocols (3 options not known UID (ID_PACE_ECDH_CAM_AES_CBC_CMAC_(128|192|256)
List<Map<String, Object>> customOIDS = [
  {'identifierString': '0.4.0.127.0.7.2.2.4.1.1', 'readableName': 'id-PACE-DH-GM-3DES-CBC-CBC',       'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 1]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.1.2', 'readableName': 'id-PACE-DH-GM-AES-CBC-CMAC-128',   'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 2]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.1.3', 'readableName': 'ID_PACE_DH_GM_AES_CBC_CMAC_192',   'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 3]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.1.4', 'readableName': 'id-PACE-DH-GM-AES-CBC-CMAC-256',   'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 4]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.3.1', 'readableName': 'id-PACE-DH-IM-3DES-CBC-CBC',       'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 1]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.3.2', 'readableName': 'id-PACE-DH-IM-AES-CBC-CMAC-128',   'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 2]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.3.3', 'readableName': 'id-PACE-DH-IM-AES-CBC-CMAC-192',   'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 3]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.3.4', 'readableName': 'id-PACE-DH-IM-AES-CBC-CMAC-256',   'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 4]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.2.1', 'readableName': 'id-PACE-ECDH-GM-3DES-CBC-CBC',     'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 1]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.2.2', 'readableName': 'id-PACE-ECDH-GM-AES-CBC-CMAC-128', 'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 2]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.2.3', 'readableName': 'id-PACE-ECDH-GM-AES-CBC-CMAC-192', 'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 3]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.2.4', 'readableName': 'id-PACE-ECDH-GM-AES-CBC-CMAC-256', 'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 4]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.4.1', 'readableName': 'id-PACE-ECDH-IM-3DES-CBC-CBC',     'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 1]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.4.2', 'readableName': 'id-PACE-ECDH-IM-AES-CBC-CMAC-128', 'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 2]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.4.3', 'readableName': 'id-PACE-ECDH-IM-AES-CBC-CMAC-192', 'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 3]},
  {'identifierString': '0.4.0.127.0.7.2.2.4.4.4', 'readableName': 'id-PACE-ECDH-IM-AES-CBC-CMAC-256', 'identifier': [0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 4]}
];


class OIEexception extends DMRTDException {
  @override
  String exceptionName = 'OIEexception';

  OIEexception(message) : super(message);
}


class ASN1ObjectIdentifierObjectException extends DMRTDException {
  @override
  String exceptionName = 'ASN1ObjectIdentifierObjectException';

  ASN1ObjectIdentifierObjectException(message) : super(message);
}

// Object Identifier Element
class OIE {
    late String identifierString;
    late String readableName;
    late List<int> identifier;

    final _log = Logger("OIE");

    OIE({required this.identifierString, required this.readableName, required this.identifier});

    OIE.fromMap({required Map<String, Object> item}){
      if (!item.containsKey('identifier') || !item.containsKey('identifierString') || !item.containsKey('readableName')) {
        _log.error('Object identifier must contain identifier, identifierString and readableName.');
        throw OIEexception('Object identifier must contain identifier, identifierString and readableName.');
      }

      if (item['identifier'] is! List<int>) {
        _log.error('Object identifier identifier must be List<int>.');
        throw OIEexception('Object identifier identifier must be List<int>.');
      }
      if (item['identifierString'] is! String) {
        _log.error('Object identifier identifierString must be String.');
        throw OIEexception('Object identifier identifierString must be String.');
      }
      if (item['readableName'] is! String) {
        _log.error('Object identifier readableName must be String.');
        throw OIEexception('Object identifier readableName must be String.');
      }

      identifierString = item['identifierString'] as String;
      readableName = item['readableName'] as String;
      identifier = item['identifier'] as List<int>;
    }

    void fromMap({required Map<String, Object> item}){
      if (!item.containsKey('identifier') || !item.containsKey('identifierString') || !item.containsKey('readableName')) {
        _log.error('Object identifier must contain identifier, identifierString and readableName.');
        throw OIEexception('Object identifier must contain identifier, identifierString and readableName.');
      }

      if (item['identifier'] is! List<int>) {
        _log.error('Object identifier identifier must be List<int>.');
        throw OIEexception('Object identifier identifier must be List<int>.');
      }
      if (item['identifierString'] is! String) {
        _log.error('Object identifier identifierString must be String.');
        throw OIEexception('Object identifier identifierString must be String.');
      }
      if (item['readableName'] is! String) {
        _log.error('Object identifier readableName must be String.');
        throw OIEexception('Object identifier readableName must be String.');
      }

      identifierString = item['identifierString'] as String;
      readableName = item['readableName'] as String;
      identifier = item['identifier'] as List<int>;
    }

    String toString() {
      return 'OIE: $identifierString, $readableName, $identifier';
    }

    bool operator ==(Object other) {
      if (other is OIE) {
        //return identifierString == other.identifierString &&
        //    readableName == other.readableName &&
        //    listEquals(identifier, other.identifier);
        return compareOnlyIdentifier(identifier: other.identifier);
      }
      return false;
    }

    bool compareOnlyIdentifier({required List<int> identifier}) {
      Function eq = const ListEquality().equals;
      return eq(this.identifier, identifier);
    }
}

enum CipherAlgorithm {
  DESede,
  AES,
}

//usage:
// var x = IV_SIZE.s128;
// print (x.value);
enum KEY_LENGTH {
  s128(16),
  s192(24),
  s256(32);

  const KEY_LENGTH(this.value);
  final num value;
}

enum TOKEN_AGREEMENT_ALGO{
  DH,
  ECDH,
}

enum MAPPING_TYPE{
  GM,
  IM,
  CAM,
}

class OIEPaceProtocol extends OIE {

  CipherAlgorithm? _cipherAlgorithm;
  KEY_LENGTH? _keyLength;
  TOKEN_AGREEMENT_ALGO? _tokenAgreementAlgorithm;
  MAPPING_TYPE? _mappingType;


  OIEPaceProtocol({required String identifierString,
                   required String readableName,
                   required List<int> identifier}) :
        super(identifierString: identifierString.toUpperCase(),
          readableName: readableName.toUpperCase(),
          identifier: identifier){
      setParams();
  }

  OIEPaceProtocol.fromMap({required Map<String, Object> item}):
                            super.fromMap(item: item){
    setParams();
  }

  void setParams(){
    switch (readableName.toUpperCase()) {
      case 'ID-PACE-DH-GM-3DES-CBC-CBC':
        _cipherAlgorithm = CipherAlgorithm.DESede;
        _keyLength = KEY_LENGTH.s128;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.DH;
        _mappingType = MAPPING_TYPE.GM;
        break;
      case 'ID-PACE-DH-GM-AES-CBC-CMAC-128':
        _cipherAlgorithm = CipherAlgorithm.AES;
        _keyLength = KEY_LENGTH.s128;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.DH;
        _mappingType = MAPPING_TYPE.GM;
        break;
      case 'ID-PACE-DH-GM-AES-CBC-CMAC-192':
        _cipherAlgorithm = CipherAlgorithm.AES;
        _keyLength = KEY_LENGTH.s192;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.DH;
        _mappingType = MAPPING_TYPE.GM;
        break;
      case 'ID-PACE-DH-GM-AES-CBC-CMAC-256':
        _cipherAlgorithm = CipherAlgorithm.AES;
        _keyLength = KEY_LENGTH.s256;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.DH;
        _mappingType = MAPPING_TYPE.GM;
        break;
      case 'id-PACE-DH-IM-3DES-CBC-CBC':
        _cipherAlgorithm = CipherAlgorithm.DESede;
        _keyLength = KEY_LENGTH.s128;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.DH;
        _mappingType = MAPPING_TYPE.IM;
        break;
      case 'ID-PACE-DH-IM-AES-CBC-CMAC-128':
        _cipherAlgorithm = CipherAlgorithm.AES;
        _keyLength = KEY_LENGTH.s128;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.DH;
        _mappingType = MAPPING_TYPE.IM;
        break;
      case 'ID-PACE-DH-IM-AES-CBC-CMAC-192':
        _cipherAlgorithm = CipherAlgorithm.AES;
        _keyLength = KEY_LENGTH.s192;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.DH;
        _mappingType = MAPPING_TYPE.IM;
        break;
      case 'ID-PACE-DH-IM-AES-CBC-CMAC-256':
        _cipherAlgorithm = CipherAlgorithm.AES;
        _keyLength = KEY_LENGTH.s256;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.DH;
        _mappingType = MAPPING_TYPE.IM;
        break;
      case 'ID-PACE-ECDH-GM-3DES-CBC-CBC':
        _cipherAlgorithm = CipherAlgorithm.DESede;
        _keyLength = KEY_LENGTH.s128;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.ECDH;
        _mappingType = MAPPING_TYPE.GM;
        break;
      case 'ID-PACE-ECDH-GM-AES-CBC-CMAC-128':
        _cipherAlgorithm = CipherAlgorithm.AES;
        _keyLength = KEY_LENGTH.s128;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.ECDH;
        _mappingType = MAPPING_TYPE.GM;
        break;
      case 'ID-PACE-ECDH-GM-AES-CBC-CMAC-192':
        _cipherAlgorithm = CipherAlgorithm.AES;
        _keyLength = KEY_LENGTH.s192;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.ECDH;
        _mappingType = MAPPING_TYPE.GM;
        break;
      case 'ID-PACE-ECDH-GM-AES-CBC-CMAC-256':
        _cipherAlgorithm = CipherAlgorithm.AES;
        _keyLength = KEY_LENGTH.s256;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.ECDH;
        _mappingType = MAPPING_TYPE.GM;
        break;
      case 'ID-PACE-ECDH-IM-3DES-CBC-CBC':
        _cipherAlgorithm = CipherAlgorithm.DESede;
        _keyLength = KEY_LENGTH.s128;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.ECDH;
        _mappingType = MAPPING_TYPE.IM;
        break;
      case 'ID-PACE-ECDH-IM-AES-CBC-CMAC-128':
        _cipherAlgorithm = CipherAlgorithm.AES;
        _keyLength = KEY_LENGTH.s128;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.ECDH;
        _mappingType = MAPPING_TYPE.IM;
        break;
      case 'ID-PACE-ECDH-IM-AES-CBC-CMAC-192':
        _cipherAlgorithm = CipherAlgorithm.AES;
        _keyLength = KEY_LENGTH.s192;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.ECDH;
        _mappingType = MAPPING_TYPE.IM;
        break;
      case 'ID-PACE-ECDH-IM-AES-CBC-CMAC-256':
        _cipherAlgorithm = CipherAlgorithm.AES;
        _keyLength = KEY_LENGTH.s256;
        _tokenAgreementAlgorithm = TOKEN_AGREEMENT_ALGO.ECDH;
        _mappingType = MAPPING_TYPE.IM;
        break;

      case 'id-PACE-ECDH-CAM-AES-CBC-CMAC-128':
        _log.error('OIEPaceProtocol; Mapping type CAM  not supported: $identifierString');
        throw OIEexception(
            'OIEPaceProtocol; Mapping type CAM  not supported: $identifierString');
      case 'id-PACE-ECDH-CAM-AES-CBC-CMAC-192':
        _log.error('OIEPaceProtocol; Mapping type CAM  not supported: $identifierString');
        throw OIEexception(
            'OIEPaceProtocol; Mapping type CAM  not supported: $identifierString');
      case 'id-PACE-ECDH-CAM-AES-CBC-CMAC-256':
        _log.error('OIEPaceProtocol; Mapping type CAM  not supported: $identifierString');
        throw OIEexception(
            'OIEPaceProtocol; Mapping type CAM  not supported: $identifierString');
      default:
        _log.error('OIEPaceProtocol; Unknown identifierString: $identifierString');
        throw OIEexception(
            'OIEPaceProtocol; Unknown identifierString: $identifierString');
    }

    _log.sdDebug("OIEPaceProtocol; identifierString: $identifierString, "
        "CipherAlgorithm: $_cipherAlgorithm, "
        "KEY_LENGTH: $_keyLength, "
        "TOKEN_AGREEMENT_ALGO: $_tokenAgreementAlgorithm, "
        "MAPPING_TYPE: $_mappingType"
    );
  }

  CipherAlgorithm get cipherAlgoritm => _cipherAlgorithm!;

  KEY_LENGTH get keyLength => _keyLength!;

  TOKEN_AGREEMENT_ALGO get tokenAgreementAlgorithm => _tokenAgreementAlgorithm!;

  MAPPING_TYPE get mappingType => _mappingType!;

  @override
  String toString() {
    return 'OIEPaceProtocol: $identifierString, $readableName, $identifier, '
        "CipherAlgorithm: $_cipherAlgorithm, "
        "KEY_LENGTH: $_keyLength, "
        "TOKEN_AGREEMENT_ALGO: $_tokenAgreementAlgorithm, "
        "MAPPING_TYPE: $_mappingType";
  }


}
/*
 * Class that handles object identifiers
 *  Singleton class
 *  Object identifiers are defined in pointycastle library
 *  Custom object identifiers can be added to existing ones
 *  Custom object identifiers must contain identifier, identifierString and readableName
 *  identifier must be List<int>
 *  identifierString and readableName must be String
 *
 *  How to use- constructor called only once:
 *    var oidType1 = ASN1ObjectIdentifierType.instance;
 */

class ASN1ObjectIdentifierType {
  // A static instance of the class
  static final ASN1ObjectIdentifierType _instance =
  ASN1ObjectIdentifierType._internal();

  // A private constructor
  ASN1ObjectIdentifierType._internal(){
    _log.info('ASN1ObjectIdentifierType constructor');
    _OIDS = _OIDS.toList();
    _log.info("OIDS from pointycastle library were added to list.");
    // add custom object identifiers to existing ones
    for (var customOID in customOIDS) {
      if (!checkOID(item:customOID)){
        throw ASN1ObjectIdentifierObjectException('Object identifier is not valid.');
      }
      _OIDS.add(customOID);
    }
  }

  // A method to get the instance
  static ASN1ObjectIdentifierType get instance => _instance;



  // object identifiers that are defined in pointycastle library
  List<Map<String, Object>> _OIDS = oi;
  final _log = Logger("ASN1ObjectIdentifierType");


  // check if object identifier is valid
  bool checkOID({required Map<String, Object> item}){
    //check if list contains all required keys
    if (!item.containsKey('identifier') || !item.containsKey('identifierString') || !item.containsKey('readableName')) {
      _log.error('Object identifier must contain identifier, identifierString and readableName.');
      return false;
    }

    if (item['identifier'] is! List<int>) {
      _log.error('Object identifier identifier must be List<int>.');
      return false;
    }
    if (item['identifierString'] is! String) {
      _log.error('Object identifier identifierString must be String.');
      return false;
    }
    if (item['readableName'] is! String) {
      _log.error('Object identifier readableName must be String.');
      return false;
    }
    return true;
  }


  // has object identifier with identifier string
  bool hasOIDWithIdentifierString({required String identifierString}) {
    _log.finer("hasOIDWithIdentifierString: $identifierString");
    return _OIDS.any((element) => element['identifierString'] == identifierString);
  }


  // get object identifier by identifier string
  Map<String, Object> getOIDByIdentifierString({required String identifierString}) {
    _log.finer("getOIDByIdentifierString: $identifierString");
    return _OIDS.firstWhere((element) => element['identifierString'] == identifierString, orElse: () =>
      throw ASN1ObjectIdentifierObjectException('Object identifier with identifier string $identifierString does not exist.'));
  }

  // has object identifier wih identifier
  bool hasOIDWithIdentifier({required List<int> identifier}) {
    _log.finer("hasOIDWithIdentifier: $identifier");
    return _OIDS.any((element) => element['identifier'] == identifier);
  }

  // get object identifier by identifier
  Map<String, Object> getOIDByIdentifier({required List<int> identifier}) {
    _log.finer("getOIDByIdentifier: $identifier");
    return _OIDS.firstWhere((element) => element['identifier'] == identifier, orElse: () =>
      throw ASN1ObjectIdentifierObjectException('Object identifier with identifier $identifier does not exist.'));
  }

}

