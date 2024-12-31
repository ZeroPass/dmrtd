// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: constant_identifier_names

import 'dart:typed_data';
import 'dg.dart';
import 'package:dmrtd/dmrtd.dart';

class EfDG15 extends DataGroup {
  static const FID = 0x010F;
  static const SFI = 0x0F;
  static const TAG = DgTag(0x6F);

  late final AAPublicKey _pubkey;
  AAPublicKey get aaPublicKey => _pubkey;

  EfDG15.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  int get fid => FID;

  @override
  int get sfi => SFI;

  @override
  int get tag => TAG.value;

  @override
  void parseContent(final Uint8List content) {
    try {
      _pubkey = AAPublicKey.fromBytes(content);
    } on Exception catch(e) {
      throw EfParseError("Failed to parse AAPublicKey from EF.DG15: $e");
    }
  }
}
