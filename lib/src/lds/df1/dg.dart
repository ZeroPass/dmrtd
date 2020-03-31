//  Created by smlu, copyright © 2020 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:meta/meta.dart';

import '../ef.dart';
import '../tlv.dart';

class DgTag {
  final int value;
  const DgTag(this.value);

  @override
  bool operator == (rhs) {
    return value == rhs.value;
  }

  @override
  int get hashCode => value;
}


abstract class DataGroup extends ElementaryFile {
  int get tag; // TLV tag
  DataGroup.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  void parse(Uint8List data) {
    final tlv = TLV.fromBytes(data);
    if(tlv.tag != tag) {
      throw EfParseError(
        "Invalid tag=${tlv.tag.toRadixString(16)}, expected tag=${tag.toRadixString(16)}"
      );
    }
    parseContent(tlv.value);
  }

  @protected
  void parseContent(final Uint8List content) {}
}