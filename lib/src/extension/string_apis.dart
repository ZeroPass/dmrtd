// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:convert';
import 'dart:core';
import 'dart:typed_data';
import 'package:convert/convert.dart';

extension StringDecodeApis on String {
  Uint8List parseBase64() {
    return base64.decode(this);
  }

  Uint8List parseHex() {
    return hex.decoder.convert(this) as Uint8List;
  }
}

extension StringYYMMDDateApi on String {
  DateTime parseDateYYMMDD() {
    if(length < 6) {
      throw FormatException("invalid length of compact date string");
    }

    int y = int.parse(substring(0, 2)) + 2000;
    int m = int.parse(substring(2, 4));
    int d = int.parse(substring(4, 6));

    // Sub 100 years from parsed year if greater than 10 years and 5 months from now.
    final now = DateTime.now();
    final tenYearsFromNow = now.year + 10;
    if (y > tenYearsFromNow ||
       (y == tenYearsFromNow && now.month + 5 < m)) {
      y -= 100;
    }
    return DateTime(y, m, d);
  }
}