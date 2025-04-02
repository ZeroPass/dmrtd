// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:convert';
import 'dart:typed_data';
import 'package:convert/convert.dart' as conv;

extension Uint8ListEncodeApis on Uint8List {
  String base64() {
    return Base64Codec().encode(this);
  }

  String hex() {
    return conv.hex.encoder.convert(this);
  }
}

extension Uint8ListDecodeApis on Uint8List {
  DateTime toDate() {
    // The date is in the format 'CCYYMMDD'
    int century = ((this[0] >> 4) * 10 + (this[0] & 0x0F)) * 100;
    int year = (this[1] >> 4) * 10 + (this[1] & 0x0F);
    int month = (this[2] >> 4) * 10 + (this[2] & 0x0F);
    int day = (this[3] >> 4) * 10 + (this[3] & 0x0F);

    return DateTime(century + year, month, day);
  }
}
