// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.

extension DateTimeYYMMDDFormatApi on DateTime {
  String formatYYMMDD() {
    var y = year.toString().substring(2, 4).padLeft(2, '0');
    var m = month.toString().padLeft(2, '0');
    var d = day.toString().padLeft(2, '0');
    return y + m + d;
  }
}