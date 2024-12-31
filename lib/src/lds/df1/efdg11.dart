// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: constant_identifier_names

import 'dart:convert';
import 'dart:core';
import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';

import 'package:dmrtd/src/lds/tlv.dart';
import 'package:dmrtd/src/lds/ef.dart';

import 'dg.dart';

class EfDG11 extends DataGroup {
  static const FID = 0x010B;
  static const SFI = 0x0B;
  static const TAG = DgTag(0x6B);

  static const FULL_NAME_TAG = 0x5F0E;
  static const OTHER_NAME_TAG = 0x5F0F;
  static const PERSONAL_NUMBER_TAG = 0x5F10;

  // In 'CCYYMMDD' format.
  static const FULL_DATE_OF_BIRTH_TAG = 0x5F2B;

  // Fields separated by '<'
  static const PLACE_OF_BIRTH_TAG = 0x5F11;

  // Fields separated by '<'
  static const PERMANENT_ADDRESS_TAG = 0x5F42;
  static const TELEPHONE_TAG = 0x5F12;
  static const PROFESSION_TAG = 0x5F13;
  static const TITLE_TAG = 0x5F14;
  static const PERSONAL_SUMMARY_TAG = 0x5F15;

  // Compressed image per ISO/IEC 10918
  static const PROOF_OF_CITIZENSHIP_TAG = 0x5F16;

  // Separated by '<'
  static const OTHER_VALID_TD_NUMBERS_TAG = 0x5F17;
  static const CUSTODY_INFORMATION_TAG = 0x5F18;

  static const TAG_LIST_TAG = 0x5c;

  String? _nameOfHolder;
  final _otherNames = <String>[];
  String? _personalNumber;
  DateTime? _fullDateOfBirth;
  final _placeOfBirth = <String>[];
  final _permanentAddress = <String>[];
  String? _telephone;
  String? _profession;
  String? _title;
  String? _personalSummary;
  Uint8List? _proofOfCitizenship;
  var _otherValidTDNumbers = <String>[];
  String? _custodyInformation;

  String? get nameOfHolder => _nameOfHolder;
  List<String> get otherNames => _otherNames;
  String? get personalNumber => _personalNumber;
  DateTime? get fullDateOfBirth => _fullDateOfBirth;
  List<String> get placeOfBirth => _placeOfBirth;
  List<String> get permanentAddress => _permanentAddress;
  String? get telephone => _telephone;
  String? get profession => _profession;
  String? get title => _title;
  String? get ersonalSummary => _personalSummary;
  Uint8List? get proofOfCitizenship => _proofOfCitizenship;
  List<String> get otherValidTDNumbers => _otherValidTDNumbers;
  String? get custodyInformation => _custodyInformation;

  EfDG11.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  int get fid => FID;

  @override
  int get sfi => SFI;

  @override
  int get tag => TAG.value;

  @override
  void parse(Uint8List content) {
    final tlv = TLV.fromBytes(content);
    if (tlv.tag != tag) {
      throw EfParseError(
          "Invalid DG11 tag=${tlv.tag.hex()}, expected tag=${TAG.value.hex()}");
    }

    final data = tlv.value;
    final tagListTag = TLV.decode(data);
    if (tagListTag.tag.value != TAG_LIST_TAG) {
      throw EfParseError(
          "Invalid version object tag=${tagListTag.tag.value.hex()}, expected version object with tag=5c");
    }
    var tagListLength = tlv.value.length;
    int tagListBytesRead = tagListTag.encodedLen;

    while (tagListBytesRead < tagListLength) {
      final uvtv = TLV.decode(data.sublist(tagListBytesRead));
      tagListBytesRead += uvtv.encodedLen;

      switch (uvtv.tag.value) {
        case FULL_NAME_TAG:
          _nameOfHolder = utf8.decode(uvtv.value);
          break;
        case PERSONAL_NUMBER_TAG:
          _personalNumber = utf8.decode(uvtv.value);
          break;
        case OTHER_NAME_TAG:
          _otherNames.add(utf8.decode(uvtv.value));
          break;
        case FULL_DATE_OF_BIRTH_TAG:
          _fullDateOfBirth = String.fromCharCodes(uvtv.value).parseDate();
          break;
        case PLACE_OF_BIRTH_TAG:
          _placeOfBirth.add(utf8.decode(uvtv.value));
          break;
        case PERMANENT_ADDRESS_TAG:
          _permanentAddress.add(utf8.decode(uvtv.value));
          break;
        case TELEPHONE_TAG:
          _telephone = utf8.decode(uvtv.value);
          break;
        case PROFESSION_TAG:
          _profession = utf8.decode(uvtv.value);
          break;
        case TITLE_TAG:
          _title = utf8.decode(uvtv.value);
          break;
        case PERSONAL_SUMMARY_TAG:
          _personalSummary = utf8.decode(uvtv.value);
          break;
        case PROOF_OF_CITIZENSHIP_TAG:
          _proofOfCitizenship = uvtv.value;
          break;
        case OTHER_VALID_TD_NUMBERS_TAG:
          _otherValidTDNumbers.add(utf8.decode(uvtv.value));
          break;
        case CUSTODY_INFORMATION_TAG:
          _custodyInformation = utf8.decode(uvtv.value);
          break;
      }
    }
  }
}
