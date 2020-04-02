//  Created by smlu, copyright © 2020 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'dg.dart';

class EfDG11 extends DataGroup {
  static const FID = 0x010B;
  static const SFI = 0x0B;
  static const TAG = DgTag(0x6B);

  EfDG11.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  int get fid => FID;

  @override
  int get sfi => SFI;

  @override
  int get tag => TAG.value;
}