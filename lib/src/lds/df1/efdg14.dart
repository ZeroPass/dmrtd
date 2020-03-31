//  Created by smlu, copyright © 2020 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'dg.dart';

class EfDG14 extends DataGroup {
  static const FID = 0x010E;
  static const SFI = 0x0E;
  static const TAG = DgTag(0x6E);

  EfDG14.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  int get fid => FID;
  
  @override
  int get sfi => SFI;

  @override
  int get tag => TAG.value;
}
