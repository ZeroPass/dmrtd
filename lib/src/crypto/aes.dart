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

  Uint8List calculateCMAC({required Uint8List data, required Uint8List key}) {
    // AES has no padding for CMAC
    final cmac = CMac(BlockCipher('AES'), 64)..init(KeyParameter(key)); //cmac mac size is fixed 64 bits
    return cmac.process(data);
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