//  Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.

import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';
import 'package:logging/logging.dart';
import 'package:pointycastle/export.dart';

import '../lds/asn1ObjectIdentifiers.dart';


class AESCipherError implements Exception {
  final String message;
  AESCipherError(this.message);
  @override
  String toString() => message;
}

enum BLOCK_CIPHER_MODE {
  ECB,
  CBC
}

/// Class implements AES encryption/decryption and CMAC calculation.
/// It uses pointycastle library for AES implementation.
/// CMAC mac size is fixed to 64 bits.
/// IV length is fixed to 128 bits in AES.
///
const int AES_BLOCK_SIZE = 16;

class AESCipher {
  static final _log = Logger("AESCipher");
  static final _factory = () => AESEngine();

  late KEY_LENGTH _size;

  AESCipher({required KEY_LENGTH size}) :
        _size = size;

  int get size {
    switch(_size) {
      case KEY_LENGTH.s128:
        return 16;
      case KEY_LENGTH.s192:
        return 24;
      case KEY_LENGTH.s256:
        return 32;
      default:
        throw AESCipherError("Invalid key size. Must be 16, 24, or 32 bytes.");
    }
  }

  //comments from docs
  // The iv must be exactly 128-bites (16 bytes) long, which is the AES block size.
  //  The key must be exactly 128-bits, 192-bits or 256-bits (i.e. 16, 24 or 32 bytes);
  //  This is what determines whether AES-128, AES-192 or AES-256 is being performed.

  Uint8List encrypt({required Uint8List data, required Uint8List key, Uint8List? iv, BLOCK_CIPHER_MODE mode = BLOCK_CIPHER_MODE.CBC, bool padding = false}) {
    _log.finest("AESCipher.encrypt; data size: ${data.length}, data: ${data.hex()}");
    _log.sdVerbose("AESCipher.encrypt; data:${data.hex()}, key size: ${key.length}, key: ${key.hex()}");

    if (key.length != size) {
      _log.error("AESCipher.encrypt; AES${size * 8} key length must be ${size * 8} bits.");
      throw AESCipherError("AESCipher.encrypt; AES${size * 8} key length must be ${size * 8} bits.");
    }

    if (iv != null) {
      _log.sdVerbose(
          "AESCipher.encrypt; iv size: ${iv.length}, iv: ${iv.hex()}");
      if (iv.length != AES_BLOCK_SIZE) {
        _log.error("AESCipher.encrypt; iv length is not 128 bits.");
        throw AESCipherError("AESCipher.encrypt; iv length is not 128 bits.");
      }
    }
    else if (mode == BLOCK_CIPHER_MODE.CBC) {
      iv = Uint8List(AES_BLOCK_SIZE);
      _log.sdVerbose("AESCipher.encrypt; iv is null");
    }
    final paddedData;
    if (padding) {
      _log.finest("Padding data with zeros to block size: $AES_BLOCK_SIZE");
      paddedData = pad(
          data: data, blockSize: AES_BLOCK_SIZE); //AES has no padding
    }
    else {
      _log.finest("Data will not be padded.");
      paddedData = data;
    }
    var cipher;
    if (mode == BLOCK_CIPHER_MODE.CBC)
      cipher = CBCBlockCipher(_factory())
        ..init(true, ParametersWithIV(KeyParameter(key), iv!));
    else
      cipher = ECBBlockCipher(_factory())..init(true, KeyParameter(key)); //ECB mode

    //return cipher.process(paddedData);
    return _processBlocks(cipher:cipher, data:paddedData);
  }

  Uint8List decrypt({required Uint8List data, required Uint8List key, Uint8List? iv, BLOCK_CIPHER_MODE mode = BLOCK_CIPHER_MODE.CBC}) {
    _log.finest("AESCipher.decrypt; data size: ${data.length}, data: ${data.hex()}");
    _log.sdVerbose("AESCipher.decrypt; data: ${data.hex()}, key size: ${key.length}, key: ${key.hex()}");

    if (key.length != size) {
      _log.error("AESCipher.decrypt; AES${size * 8} key length must be ${size * 8} bits.");
      throw AESCipherError("AESCipher.decrypt; AES${size * 8} key length must be ${size * 8} bits.");
    }

    if (iv != null){
      _log.sdVerbose("AESCipher.decrypt; iv size: ${iv.length}, iv: ${iv.hex()}");
      if (iv.length != AES_BLOCK_SIZE) {
        _log.error("AESCipher.encrypt; iv length is not 128 bits.");
        throw AESCipherError("AESCipher.encrypt; iv length is not 128 bits.");
      }
    }
    else {
      iv = Uint8List(AES_BLOCK_SIZE);
      _log.sdVerbose("AESCipher.decrypt; iv is null");
    }

    var cipher;
    if (mode == BLOCK_CIPHER_MODE.CBC)
      cipher = CBCBlockCipher(_factory())
        ..init(false, ParametersWithIV(KeyParameter(key), iv));
    else
      cipher = ECBBlockCipher(_factory())..init(false, KeyParameter(key));
      return Uint8List.fromList(_processBlocks(cipher:cipher, data:data).toList());
  }

  Uint8List _processBlocks({required BlockCipher cipher, required Uint8List data}) {
    _log.finest("AESCipher._processBlocks; data size: ${data.length}");
    _log.sdVerbose("AESCipher._processBlocks; data: ${data.hex()}");
    final output = Uint8List(data.length);

    for (int i = 0; i < data.length; i += cipher.blockSize) {
      cipher.processBlock(data, i, output, i);
    }
    _log.sdVerbose("AESCipher._processBlocks; output data: ${output.hex()}");

    return output;
  }

  Uint8List pad({required Uint8List data, int blockSize = AES_BLOCK_SIZE }) {
    _log.finest("Padding data with zeros to block size: $blockSize");
    _log.sdVerbose("Data to pad: ${data.hex()} ");
    final padLength = blockSize - (data.length % blockSize);
    List<int> list = data.toList()..addAll(List.filled(padLength, 0));
    return Uint8List.fromList(list);
  }

  /// Calculates AES-CMAC (NIST SP 800-38B) over [data] and returns the
  /// 8 most significant bytes (ICAO 9303-11 4.4.3.4 and 9.8.7.2).
  /// Works with 128, 192 and 256-bit keys.
  ///
  /// Note: pointycastle's CMac is not used here because its init() creates the
  /// zero IV with the length of the key instead of the block size, which throws
  /// for 192 and 256-bit keys (https://github.com/bcgit/pc-dart/issues/200).
  Uint8List calculateCMAC({required Uint8List data, required Uint8List key}) {
    return _cmac(data: data, key: key).sublist(0, 8); //cmac mac size is fixed 64 bits
  }

  /// Full 16-byte AES-CMAC according to NIST SP 800-38B, sections 6.1 and 6.2.
  static Uint8List _cmac({required Uint8List data, required Uint8List key}) {
    if (key.length != 16 && key.length != 24 && key.length != 32) {
      throw AESCipherError("AESCipher._cmac; invalid AES key length: ${key.length}");
    }
    final aes = AESEngine()..init(true, KeyParameter(key));

    Uint8List encryptBlock(Uint8List block) {
      final out = Uint8List(AES_BLOCK_SIZE);
      aes.processBlock(block, 0, out, 0);
      return out;
    }

    // Doubling in GF(2^128), R_128 = 0x87
    Uint8List dbl(Uint8List block) {
      final out = Uint8List(AES_BLOCK_SIZE);
      var carry = 0;
      for (var i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
        out[i] = ((block[i] << 1) | carry) & 0xFF;
        carry = (block[i] >> 7) & 1;
      }
      if ((block[0] & 0x80) != 0) {
        out[AES_BLOCK_SIZE - 1] ^= 0x87;
      }
      return out;
    }

    // Subkeys K1 and K2
    final k1 = dbl(encryptBlock(Uint8List(AES_BLOCK_SIZE)));
    final k2 = dbl(k1);

    final n = data.isEmpty ? 1 : (data.length + AES_BLOCK_SIZE - 1) ~/ AES_BLOCK_SIZE;
    final isComplete = data.isNotEmpty && data.length % AES_BLOCK_SIZE == 0;
    final lastOffset = (n - 1) * AES_BLOCK_SIZE;

    // Last block: XOR with K1 if complete, otherwise pad with 0x80 00..00 and XOR with K2
    final last = Uint8List(AES_BLOCK_SIZE);
    final remaining = data.length - lastOffset;
    for (var i = 0; i < AES_BLOCK_SIZE; i++) {
      if (isComplete) {
        last[i] = data[lastOffset + i] ^ k1[i];
      } else {
        final b = i < remaining ? data[lastOffset + i] : (i == remaining ? 0x80 : 0x00);
        last[i] = b ^ k2[i];
      }
    }

    var x = Uint8List(AES_BLOCK_SIZE);
    for (var j = 0; j < n; j++) {
      final y = Uint8List(AES_BLOCK_SIZE);
      for (var i = 0; i < AES_BLOCK_SIZE; i++) {
        y[i] = x[i] ^ (j == n - 1 ? last[i] : data[j * AES_BLOCK_SIZE + i]);
      }
      x = encryptBlock(y);
    }
    return x;
  }
}

class AESCipher128 extends AESCipher {
  AESCipher128() : super(size: KEY_LENGTH.s128);
}

class AESCipher192 extends AESCipher {
  AESCipher192() : super(size: KEY_LENGTH.s192);
}

class AESCipher256 extends AESCipher {
  AESCipher256() : super(size: KEY_LENGTH.s256);
}

class AESChiperSelector{
  static final _log = Logger("AESChiperSelector");

  static AESCipher getChiper({required KEY_LENGTH size}) {
    switch (size) {
      case KEY_LENGTH.s128:
        _log.finer("AES chiper with 128-bit key size selected.");
        return AESCipher128();
      case KEY_LENGTH.s192:
        _log.finer("AES chiper with 192-bit key size selected.");
        return AESCipher128();
      case KEY_LENGTH.s256:
        _log.finer("AES chiper with 256-bit key size selected.");
        return AESCipher256();

      default:
        _log.error("AESChiperSelector; Size is not supported.");
        throw AESCipherError("AESChiperSelector; Size is not supported.");
    }
  }
}