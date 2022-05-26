// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: constant_identifier_names

import 'dart:typed_data';
import 'dg.dart';

class EfDG2 extends DataGroup {
  static const FID = 0x0102;
  static const SFI = 0x02;
  static const TAG = DgTag(0x75);

  EfDG2.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  int get fid => FID;

  @override
  int get sfi => SFI;

  @override
  int get tag => TAG.value;
}
