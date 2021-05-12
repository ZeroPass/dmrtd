// Created by Crt Vavros, copyright © 2021 ZeroPass. All rights reserved.
import 'dart:convert';
import 'dart:typed_data';
import 'package:convert/convert.dart' as C;

extension Uint8ListEncodeApis on Uint8List {
  String base64() {
    return Base64Codec().encode(this);
  }

  String hex() {
    return C.hex.encoder.convert(this);
  }
}