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