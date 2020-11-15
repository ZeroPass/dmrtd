extension IntApis on int {
  String hex() {
    final str = toRadixString(16);
    final padded_len = (str.length.isOdd ? 1 : 0) + str.length;
    return str.padLeft(padded_len, '0').toUpperCase();
  }
}