//  Created by smlu, copyright © 2020 ZeroPass. All rights reserved.
import 'dart:core';
import 'dart:typed_data';

import 'dg.dart';
import '../ef.dart';
import '../tlv.dart';

class EfSOD extends ElementaryFile {
  static const FID = 0x011D;
  static const SFI = 0x1D;
  static const TAG = 0x77;

  EfSOD.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  int get fid => FID;

  @override
  int get sfi => SFI;
}
