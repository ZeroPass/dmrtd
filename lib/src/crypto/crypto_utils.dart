//  Copyright © 2020 ZeroPass. All rights reserved.
import 'dart:math';
import 'dart:typed_data';

Uint8List randomBytes(int length) {
  final random = Random.secure();
    var intBytes = List<int>.generate(length, (i) => random.nextInt(256));
    return Uint8List.fromList(intBytes);
}