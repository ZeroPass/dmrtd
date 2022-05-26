//  Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:meta/meta.dart';

class EfParseError implements Exception {
  final String message;
  EfParseError(this.message);
  @override
  String toString() => message;
}

abstract class ElementaryFile{

  int get fid; // file id
  int get sfi; // short file id
  final Uint8List _encoded;

  ElementaryFile.fromBytes(final Uint8List data) : _encoded = data {
    parse(data);
  }

  Uint8List toBytes() {
    return _encoded;
  }

  @protected
  void parse(final Uint8List content);
}