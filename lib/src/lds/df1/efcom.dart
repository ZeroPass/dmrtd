// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: constant_identifier_names

import 'dart:core';
import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';

import 'dg.dart';
import '../ef.dart';
import '../tlv.dart';

class EfCOM extends ElementaryFile {
  static const FID = 0x011E;
  static const SFI = 0x1E;
  static const TAG = 0x60;

  late final String _ver;
  late final String _uver;
  final _tags = <DgTag>{};

  get version => _ver;
  get unicodeVersion => _uver;
  Set<DgTag> get dgTags => _tags;

  EfCOM.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  int get fid => FID;

  @override
  int get sfi => SFI;

  @override
  void parse(final Uint8List content) {
    final tlv = TLV.fromBytes(content);
    if(tlv.tag != TAG) {
      throw EfParseError(
        "Invalid EF.COM tag=${tlv.tag.hex()}, expected tag=${TAG.hex()}"
      );
    }

    // Parse version number
    final data = tlv.value;
    final vtv = TLV.decode(data);
    if(vtv.tag.value != 0x5F01) {
      throw EfParseError(
        "Invalid version object tag=${vtv.tag.value.hex()}, expected version object with tag=5F01"
      );
    }
    _ver = String.fromCharCodes(vtv.value);

    // Parse string version
    final uvtv = TLV.decode(data.sublist(vtv.encodedLen));
    if(uvtv.tag.value != 0x5F36) {
      throw EfParseError(
        "Invalid unicode version object tag=${uvtv.tag.value.hex()}, expected unicode version object with tag=5F36"
      );
    }
    _uver = String.fromCharCodes(uvtv.value);

    // Parse tag list
    final tvTagList = TLV.decode(data.sublist(vtv.encodedLen + uvtv.encodedLen));
    if(tvTagList.tag.value != 0x5C) {
      throw EfParseError(
        "Invalid tag list object tag=${tvTagList.tag.value.hex()}, expected tag list object with tag=5C"
      );
    }

    // fill _tags set.
    // Each tag should be represented as 1 byte
    for(final t in tvTagList.value) {
      _tags.add(DgTag(t));
    }
  }
}
