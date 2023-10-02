// Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.

import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';
import 'package:logging/logging.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/asn1/object_identifiers_database.dart';

import '../../types/exception.dart';


// here you can add additional object identifiers that are not defined in pointycastle library
List<Map<String, Object>> customOIDS = [
{
'identifierString': '1.2.3.4.5',  'readableName': 'someName', 'identifier': [0, 1, 2, 3, 4, 5]
}
];


// add additional object identifiers

class ASN1ObjectIdentifierException implements DMRTDException {
  final String message;
  @override
  String exceptionName = 'ASN1ObjectIdentifierException';

  ASN1ObjectIdentifierException(this.message);
  //@override
  //String toString() {
  //  String result = 'ASN1ObjectIdentifierException';
  //  if (message is String) return '$result: $message';
  //  return result;
  //}


}


class ASN1ObjectIdentifiers {
  // object identifiers that are defined in pointycastle library
  List<Map<String, Object>> _OIDS = oi;
  final _log = Logger("ASN1ObjectIdentifiers");
  
  
  ASN1ObjectIdentifiers(){
    // add custom object identifiers to existing ones
    for (var customOID in customOIDS) {
      if (!checkOID(item:customOID)){
        throw ASN1ObjectIdentifierException('Object identifier is not valid.');
      }
      _OIDS.add(customOID);
    }
  }

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
  bool hasOIDWithIdentifierString(String identifierString) {
    return _OIDS.any((element) => element['identifierString'] == identifierString);
  }


  // get object identifier by identifier string
  Map<String, Object> getOIDByIdentifierString(String identifierString) {
    return _OIDS.firstWhere((element) => element['identifierString'] == identifierString, orElse: () =>
      throw ASN1ObjectIdentifierException('Object identifier with identifier string $identifierString does not exist.'));
  }

  // has object identifier wih identifier
  bool hasOIDWithIdentifier(List<int> identifier) {
    return _OIDS.any((element) => element['identifier'] == identifier);
  }

  // get object identifier by identifier
  Map<String, Object> getOIDByIdentifier(List<int> identifier) {
    return _OIDS.firstWhere((element) => element['identifier'] == identifier, orElse: () =>
      throw ASN1ObjectIdentifierException('Object identifier with identifier $identifier does not exist.'));
  }

}

