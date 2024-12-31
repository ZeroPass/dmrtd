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
  DateTime parseDateYYMMDD({bool futureDate = false}) {
    if (length < 6) {
      throw FormatException("Invalid length of compact date string");
    }

    int y = int.parse(substring(0, 2)) + 2000;
    int m = int.parse(substring(2, 4));
    int d = int.parse(substring(4, 6));

    final now = DateTime.now();
    int maxYear  = now.year;
    int maxMonth = now.month;
    if (futureDate) {
      maxYear  += 20; // cut off year 20 years from now
      maxMonth += 5;
    }

    // If parsed year is greater than max wind back for 100 years
    if (y > maxYear || ( y == maxYear && maxMonth < m)) {
      y -= 100;
    }

    return DateTime(y, m, d);
  }

  DateTime parseDate({bool futureDate = false}) {
    if (length == 6) {
      return this.parseDateYYMMDD(futureDate: futureDate);
    } else {
      return DateTime.parse(this);
    }
  }
}
