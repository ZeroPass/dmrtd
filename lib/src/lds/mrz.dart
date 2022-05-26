//  Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'package:archive/archive.dart';
import 'dart:core';
import 'dart:typed_data';

import '../extension/datetime_apis.dart';
import '../extension/string_apis.dart';

enum MRZVersion { td1, td2, td3 }
class MRZParseError implements Exception {
  final String message;
  MRZParseError(this.message);
  @override
  String toString() => message;
}

class MRZ {
  late final String country;
  late final DateTime dateOfBirth;
  late final DateTime dateOfExpiry;
  late final String documentCode;
  String get documentNumber => _docNum;
  late final String firstName;
  late final String lastName;
  late final String nationality;
  String get optionalData => _optData;
  String? get optionalData2 => _optData2;
  late final String gender;
  late final MRZVersion version;
  late String _docNum;
  late String _optData;
  String? _optData2;

  MRZ(Uint8List encodedMRZ) {
    _parse(encodedMRZ);
  }

  static int calculateCheckDigit(String checkString)  {
    const charMap = {
      "0" :  "0",  "1" :  "1",
      "2" :  "2",  "3" :  "3",
      "4" :  "4",  "5" :  "5",
      "6" :  "6",  "7" :  "7",
      "8" :  "8",  "9" :  "9",
      "<" :  "0",  " " :  "0",
      "A" : "10",  "B" : "11",
      "C" : "12",  "D" : "13",
      "E" : "14",  "F" : "15",
      "G" : "16",  "H" : "17",
      "I" : "18",  "J" : "19",
      "K" : "20",  "L" : "21",
      "M" : "22",  "N" : "23",
      "O" : "24",  "P" : "25",
      "Q" : "26",  "R" : "27",
      "S" : "28",  "T" : "29",
      "U" : "30",  "V" : "31",
      "W" : "32",  "X" : "33",
      "Y" : "34",  "Z" : "35"
    };

    var sum = 0;
    var m   = 0;
    const multipliers = [7, 3, 1];
    for (int i = 0; i < checkString.length; i++) {
      final lookup = charMap[checkString[i]];
      final number = int.tryParse(lookup ?? "");
      if(number == null) {
        return 0;
      }

      final product = number * multipliers[m];
      sum += product;
      m = (m + 1) % multipliers.length;
    }
    return (sum % 10);
  }

  void _parse(Uint8List data) {
    final istream = InputStream(data);
    if (data.length == 90) {
      version = MRZVersion.td1;
      _parseTD1(istream);
    }
    else if (data.length == 72) {
      version = MRZVersion.td2;
      _parseTD2(istream);
    }
    else if (data.length == 88) {
      version = MRZVersion.td3;
      _parseTD3(istream);
    }
    else {
      throw MRZParseError("Invalid MRZ data");
    }
  }

  void _parseTD1(InputStream istream) {
    documentCode   = _read(istream, 2);
    country        = _read(istream, 3);
    _docNum        = _read(istream, 9);
    final cdDocNum = _readWithPad(istream, 1);
    _optData       = _read(istream, 15);
    dateOfBirth    = _readDate(istream);

    _assertCheckDigit(dateOfBirth.formatYYMMDD(), _readCD(istream),
      "Data of Birth check digit mismatch"
    );

    gender            = _read(istream, 1);
    dateOfExpiry   = _readDate(istream);

    _assertCheckDigit(dateOfExpiry.formatYYMMDD(), _readCD(istream),
      "Data of Expiry check digit mismatch"
    );

    nationality = _read(istream, 3);
    _optData2   = _read(istream, 11);
    _parseExtendedDocumentNumber(cdDocNum);

    final cdComposite = _readCD(istream);
    _setNames(_readNameIdentifiers(istream, 30));

    // Extract composite and calculate/verify its CD
    istream.reset();
    istream.skip(5);
    var composite = _readWithPad(istream, 25);
    composite += _readWithPad(istream, 7);
    istream.skip(1);
    composite += _readWithPad(istream, 7);
    istream.skip(3);
    composite += _readWithPad(istream, 11);
    _assertCheckDigit(composite, cdComposite,
      "Composite check digit mismatch"
    );
  }

  void _parseTD2(InputStream istream) {
    documentCode   = _read(istream, 2);
    country        = _read(istream, 3);
    _setNames(_readNameIdentifiers(istream, 31));

    _docNum        = _read(istream, 9);
    final cdDocNum = _readWithPad(istream, 1);

    nationality    = _read(istream, 3);
    dateOfBirth    = _readDate(istream);
    _assertCheckDigit(dateOfBirth.formatYYMMDD(), _readCD(istream),
      "Data of Birth check digit mismatch"
    );

    gender            = _read(istream, 1);
    dateOfExpiry   = _readDate(istream);
    _assertCheckDigit(dateOfExpiry.formatYYMMDD(), _readCD(istream),
      "Data of Expiry check digit mismatch"
    );

    _optData = _read(istream, 7);
    _parseExtendedDocumentNumber(cdDocNum);

    final cdComposite = _readCD(istream);

    // Extract composite and calculate/verify its CD
    istream.rewind(36);
    var composite = _readWithPad(istream, 10);
    istream.skip(3);
    composite += _readWithPad(istream, 7);
    istream.skip(1);
    composite += _readWithPad(istream, 14);
    _assertCheckDigit(composite, cdComposite,
      "Composite check digit mismatch"
    );
  }

  void _parseTD3(InputStream istream) {
    documentCode   = _read(istream, 2);
    country        = _read(istream, 3);
    _setNames(_readNameIdentifiers(istream, 39));

    _docNum = _read(istream, 9);
    _assertCheckDigit(_docNum, _readCD(istream),
      "Document Number check digit mismatch"
    );

    nationality    = _read(istream, 3);
    dateOfBirth    = _readDate(istream);
    _assertCheckDigit(dateOfBirth.formatYYMMDD(), _readCD(istream),
      "Data of Birth check digit mismatch"
    );

    gender            = _read(istream, 1);
    dateOfExpiry   = _readDate(istream);
    _assertCheckDigit(dateOfExpiry.formatYYMMDD(), _readCD(istream),
      "Data of Expiry check digit mismatch"
    );

    _optData = _read(istream, 14);
    _assertCheckDigit(_optData, _readCD(istream),
      "Optional data check digit mismatch"
    );

    final cdComposite = _readCD(istream);

    // Extract composite and calculate/verify its CD
    istream.rewind(44);
    var composite = _readWithPad(istream, 10);
    istream.skip(3);
    composite += _readWithPad(istream, 7);
    istream.skip(1);
    composite += _readWithPad(istream, 22);
    _assertCheckDigit(composite, cdComposite,
      "Composite check digit mismatch"
    );
  }

  void _setNames(List<String> nameIds) {
    if (nameIds.isNotEmpty) {
      lastName = nameIds[0];
    }
    if (nameIds.length > 1) {
      firstName = nameIds.sublist(1).join(' ');
    }
  }

  void _parseExtendedDocumentNumber(String strCdDocNum) {
    int cdDocNum = 0;
    if(strCdDocNum == '<' && _optData.length > 2) {
      final dnSecondPart = _optData.split('<')[0];
      _docNum += dnSecondPart.substring(0, dnSecondPart.length - 1);

      cdDocNum  = int.parse(dnSecondPart[dnSecondPart.length - 1]);
      _optData  = _optData2 ?? '';
      _optData2 = null;
    }
    else {
      cdDocNum = int.parse(strCdDocNum);
    }

    _assertCheckDigit(_docNum, cdDocNum,
      "Document Number check digit mismatch"
    );
  }

  static String _read(InputStream istream, int maxLength) {
    return _readWithPad(istream, maxLength).replaceAll(RegExp(r'<+$'), '');
  }

  static DateTime _readDate(InputStream istream) {
    return _read(istream, 6).parseDateYYMMDD();
  }

  static int _readCD(InputStream istream) {
    var scd = _readWithPad(istream, 1);
    if (scd == '<') return 0;
    return int.tryParse(scd) ?? (throw MRZParseError("Invalid check digit character in MRZ"));
  }

  static List<String> _readNameIdentifiers(InputStream istream, int maxLength) {
    final nameField = _read(istream, maxLength);
    var ids = nameField.split("<<");
    for (int i = 0; i < ids.length; i++) {
      ids[i] = ids[i].replaceAll('<', ' ');
    }
    return ids;
  }

  static String _readWithPad(InputStream istream, int maxLength) {
    return istream.readString(size: maxLength, utf8: false);
  }

  static void _assertCheckDigit(String value, int cdigit, String errorMsg) {
    if (calculateCheckDigit(value) != cdigit) {
      throw MRZParseError(errorMsg);
    }
  }
}