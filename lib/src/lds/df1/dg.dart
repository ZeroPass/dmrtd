// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:meta/meta.dart';
import 'package:dmrtd/extensions.dart';

import '../ef.dart';
import '../tlv.dart';

class DgTag {
  final int value;
  const DgTag(this.value);

  @override
  bool operator == (covariant DgTag other) {
    return value == other.value;
  }

  @override
  int get hashCode => value;
}


abstract class DataGroup extends ElementaryFile {
  int get tag; // TLV tag
  DataGroup.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  void parse(Uint8List content) {
    final tlv = TLV.fromBytes(content);
    if(tlv.tag != tag) {
      throw EfParseError(
        "Invalid tag=${tlv.tag.hex()}, expected tag=${tag.hex()}"
      );
    }
    parseContent(tlv.value);
  }

  @protected
  void parseContent(final Uint8List content) {}
}