//  Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:tripledes_nullsafety/tripledes_nullsafety.dart';
import 'iso9797.dart';

/// Implements DES encryption algorithm using CBC block cipher mode
class DESCipher {
  static const blockSize = 8;

  late List<int> _iv;
  late List<int> _key;
  final BaseEngine _bc = DESEngine();

  /// Creates a [DESCipher] with [key] and initial vector [iv].
  ///
  /// [key] length must be 8 bytes.
  /// [iv] length must be 8 bytes.
  DESCipher({required final Uint8List key, required final Uint8List iv}) {
    this.key = key;
    this.iv = iv;
  }

  /// Returns current key
  Uint8List get key {
    return _dwordListToBytes(_key);
  }

  /// Sets new key. The [key] length must be 8 bytes.
  set key(final Uint8List key) {
    if (key.length != blockSize) {
      throw ArgumentError.value(key, "key length should be $blockSize bytes");
    }
    _key = _bytesToDWordList(key);
  }

  /// Returns current iv.
  Uint8List get iv {
    return _dwordListToBytes(_iv);
  }

  /// Sets new iv. The [iv] length must be 8 bytes.
  set iv(final Uint8List iv) {
    if (iv.length != blockSize) {
      throw ArgumentError.value(
          iv, "invalid IV length should be $blockSize bytes");
    }
    _iv = _bytesToDWordList(iv);
  }

  /// Returns encrypted [data].
  ///
  /// The [data] if [padData] is set to false should be padded to the nearest multiple of 8.
  /// When [padData] is true, the [data] is padded according to the ISO/IEC 9797-1, padding method 2.
  Uint8List encrypt(final Uint8List data, {final bool padData = true}) {
    _bc.init(true, _key);
    return _process(_padOrRef(data, padData));
  }

  /// Returns decrypted [edata].
  ///
  /// When [paddedData] is true, function expects decrypted [edata] is padded according to
  /// the ISO/IEC 9797-1, padding method 2 and will attempt to unpad it (see encrypt).
  Uint8List decrypt(final Uint8List edata, {final bool paddedData = true}) {
    _bc.init(false, _key);
    return _unpadOrRef(_process(edata), paddedData);
  }

  // Returns encrypted [block]. The [block] size must be 8 bytes.
  Uint8List encryptBlock(final Uint8List block) {
    if (block.length % blockSize != 0) {
      throw ArgumentError.value(block, "block size should be $blockSize bytes");
    }
    _bc.init(true, _key);
    final wblock = _bytesToDWordList(block);
    _processBlock(wblock);
    return _dwordListToBytes(wblock);
  }

  // Returns decrypted [eblock].
  Uint8List decryptBlock(final Uint8List eblock) {
    if (eblock.length % blockSize != 0) {
      throw ArgumentError.value(
          eblock, "eblock size should be $blockSize bytes");
    }
    _bc.init(false, _key);
    final wblock = _bytesToDWordList(eblock);
    _processBlock(wblock);
    return _dwordListToBytes(wblock);
  }

  /// block should be list of 2 ints
  void _processBlock(final List<int> block) {
    _bc.processBlock(block, 0);
  }

  /// Encrypts/decrypts [data] using CBC block cipher mode.
  Uint8List _process(final Uint8List data) {
    if (data.length % blockSize != 0) {
      throw ArgumentError.value(
          data, "data size should be multiple of $blockSize bytes");
    }

    List<int> pdata = List<int>.empty(growable: true);
    List<int> xord = _iv;
    final size = data.length / blockSize;
    for (int i = 0; i < size; i++) {
      final block =
          _bytesToDWordList(data.sublist(i * blockSize, i * blockSize + 8));

      // copy current block - to be used for CBC xoring when decrypting
      List<int> pblock = List.from(block);

      // CBC
      if (_bc.forEncryption) {
        // xor block with previous encrypted block
        _xorBlock(block, xord);
      }

      // Encrypt/decrypt block
      _processBlock(block);

      // CBC
      if (_bc.forEncryption) {
        xord = block;
      } else {
        // decryption
        // xor block with previous encrypted block
        _xorBlock(block, xord);
        xord = pblock;
      }

      pdata += block;
    }

    return _dwordListToBytes(pdata);
  }

  Uint8List _padOrRef(final Uint8List data, final bool padData) {
    if (padData) {
      return ISO9797.pad(data);
    }
    return data;
  }

  Uint8List _unpadOrRef(final Uint8List data, final bool unpadData) {
    if (unpadData) {
      return ISO9797.unpad(data);
    }
    return data;
  }

  void _xorBlock(final List<int> block, final List<int> xdata) {
    if (block.length != xdata.length) {
      throw ArgumentError.value(
          xdata, "invalid length pf data to xor block with");
    }
    for (int i = 0; i < block.length; i++) {
      block[i] ^= xdata[i];
    }
  }

  static List<int> _bytesToDWordList(final Uint8List bytes) {
    final dwords = List<int>.filled((bytes.length / 4).round(), 0);
    final view = ByteData.view(bytes.buffer);
    for (int i = 0; i < dwords.length; i++) {
      dwords[i] = view.getInt32(i * 4);
    }
    return dwords;
  }

  static Uint8List _dwordListToBytes(final List<int> dwords) {
    final bytes = Uint8List(dwords.length * 4);
    final view = ByteData.view(bytes.buffer);
    for (int i = 0; i < dwords.length; i++) {
      view.setInt32(i * 4, dwords[i], Endian.big);
    }
    return bytes;
  }
}

/// Implements Triple DES encryption algorithm using CBC block cipher mode
class DESedeCipher extends DESCipher {
  static const blockSize = DESCipher.blockSize;

  /// Creates a [DESedeCipher] with [key] and initial vector [iv].
  ///
  /// [key] length must be 8, 16 or 24 bytes.
  /// [iv] length must be 8 bytes.
  DESedeCipher({required final Uint8List key, required final Uint8List iv})
      : super(key: key, iv: iv);

  /// Sets new key. [key] length must be 8, 16 or 24 bytes.
  @override
  set key(final Uint8List key) {
    if (key.length % 8 != 0 || key.length > 24) {
      throw ArgumentError.value(key, "key length should be 8, 16 or 24 bytes");
    }

    _key = DESCipher._bytesToDWordList(key);
    if (key.length == 16) {
      // Keying option 2
      _key += _key.sublist(0, 2);
    }

    if (key.length == 8) {
      // Keying option 3
      _key += _key.sublist(0, 2) + _key.sublist(0, 2);
    }
  }

  /// Block should be list of 2 ints
  @override
  void _processBlock(final List<int> block) {
    if (_bc.forEncryption) {
      _bc.init(true, _key.sublist(0, 2));
      _bc.processBlock(block, 0);
      _bc.init(false, _key.sublist(2, 4));
      _bc.processBlock(block, 0);
      _bc.init(true, _key.sublist(4, 6));
      _bc.processBlock(block, 0);
    } else {
      _bc.init(false, _key.sublist(4, 6));
      _bc.processBlock(block, 0);
      _bc.init(true, _key.sublist(2, 4));
      _bc.processBlock(block, 0);
      _bc.init(false, _key.sublist(0, 2));
      _bc.processBlock(block, 0);
    }
  }
}

/// Returns encrypted [data] using Triple DES encryption algorithm and CBD block cipher mode.
///
/// The [data] if [padData] is set to false should be padded to the nearest multiple of 8.
/// When [padData] is true, the [data] is padded according to the ISO/IEC 9797-1, padding method 2.
// ignore: non_constant_identifier_names
Uint8List DESedeEncrypt(
    {required final Uint8List key,
    required final Uint8List iv,
    required final Uint8List data,
    bool padData = true}) {
  return DESedeCipher(key: key, iv: iv).encrypt(data, padData: padData);
}

/// Returns decrypted [data] using Triple DES encryption algorithm and CBD block cipher mode.
///
/// The [data] if [padData] is set to false should be padded to the nearest multiple of 8.
/// When [padData] is true, the [data] is padded according to the ISO/IEC 9797-1, padding method 2.
// ignore: non_constant_identifier_names
Uint8List DESedeDecrypt(
    {required final Uint8List key,
    required final Uint8List iv,
    required final Uint8List edata,
    bool paddedData = true}) {
  return DESedeCipher(key: key, iv: iv).decrypt(edata, paddedData: paddedData);
}
