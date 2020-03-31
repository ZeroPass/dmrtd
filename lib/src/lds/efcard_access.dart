//  Created by smlu, copyright © 2020 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'ef.dart';

class EfCardAccess extends ElementaryFile {
  static const FID = 0x011C;
  static const SFI = 0x1C;

  EfCardAccess.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  int get fid => FID;
  
  @override
  int get sfi => SFI;
}