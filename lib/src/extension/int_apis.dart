//  Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.

extension IntApis on int {
  String hex() {
    final str = toRadixString(16);
    final paddedLen = (str.length.isOdd ? 1 : 0) + str.length;
    return str.padLeft(paddedLen, '0').toUpperCase();
  }
}