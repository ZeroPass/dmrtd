// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: constant_identifier_names

import 'dart:typed_data';
import 'ef.dart';

class EfCardSecurity extends ElementaryFile {
  static const FID = 0x011D;
  static const SFI = 0x1D;

  EfCardSecurity.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  int get fid => FID;

  @override
  int get sfi => SFI;

  @override
  void parse(Uint8List content) {}
}
