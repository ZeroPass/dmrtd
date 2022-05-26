// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import '../utils.dart';

/// Decoded tag
class DecodedTag {
  final int value;
  final int encodedLen; // number of bytes it took to encode tag
  DecodedTag(this.value, this.encodedLen);
}

/// Decoded len
class DecodedLen {
  final int value;
  final int encodedLen; // number of bytes it took to encode length
  DecodedLen(this.value, this.encodedLen);
}

/// Decoded tag and value
class DecodedTV {
  final DecodedTag tag;
  final Uint8List value;
  final int
      encodedLen; // number of bytes it took to encode tag, value length and value
  DecodedTV(this.tag, this.value, this.encodedLen);
}

/// Decoded tag and value length
class DecodedTL {
  final DecodedTag tag;
  final DecodedLen length;
  final int encodedLen; // number of bytes it took to encode tag and value length
  DecodedTL(this.tag, this.length, this.encodedLen);
}

/// Thrown when tag and data can't be encoded or decoded.
class TLVError implements Exception {
  final String message;
  TLVError(this.message);
  @override
  String toString() => message;
}

/// Class Represents BER-TLV encoding/decoding functions.
class TLV {
  int tag;
  Uint8List value;

  TLV(this.tag, this.value) {
    // TODO: check that tag and value can be encoded, and throw if not
  }

  /// Returns decoded [TLV] from [encodedTLV] bytes.
  /// throws [TLVError] if [encodedTLV] is empty or if encoding of tag/length is invalid.
  factory TLV.fromBytes(final Uint8List encodedTLV) {
    final tv = decode(encodedTLV);
    return TLV(tv.tag.value, tv.value);
  }

  /// Constructs [TLV] from [tag] and integer [n] as value.
 /// [n] is serialized in big endian byte order.
  factory TLV.fromIntValue(final int tag, int n) {
    return TLV(tag, Utils.intToBin(n));
  }

  Uint8List toBytes() {
    return encode(tag, value);
  }

  /// Returns BER encoded TLV from [tag] and [data].
  static Uint8List encode(final int tag, final Uint8List data) {
    final t = encodeTag(tag);
    final l = encodeLength(data.length);
    return Uint8List.fromList(t + l + data);
  }

  /// Returns BER encoded TLV from [tag] and [n].
  /// [n] is serialized in big endian byte order.
  static Uint8List encodeIntValue(final int tag, final int n) {
    return TLV.fromIntValue(tag, n).toBytes();
  }

  /// Returns decoded BER-TLV encoded tag, value and number of bytes encoded TLV took.
  /// throws [TLVError] if [encodedTLV] is empty or if encoding of tag/length is invalid.
  static DecodedTV decode(final Uint8List encodedTLV) {
    final tl = decodeTagAndLength(encodedTLV);
    final data = encodedTLV.sublist(tl.encodedLen, tl.encodedLen + tl.length.value);
    return DecodedTV(tl.tag, data, tl.encodedLen + data.length);
  }

  /// Returns decoded tag, length and number of bytes encoded tag and length took.
  /// throws [TLVError] if [encodedTLV] is empty or if encoding of tag/length is invalid.
  static DecodedTL decodeTagAndLength(final Uint8List encodedTagLength) {
    final tag = decodeTag(encodedTagLength);
    final len = decodeLength(encodedTagLength.sublist(tag.encodedLen));
    return DecodedTL(tag, len, tag.encodedLen + len.encodedLen);
  }

  /// Returns BER encoded [tag];
  static Uint8List encodeTag(final int tag) {
    final byteCount = Utils.byteCount(tag);
    var encodedTag  = Uint8List(byteCount == 0 ? 1 : byteCount);
    for (int i = 0; i < byteCount; i++) {
      final pos = 8 * (byteCount - i - 1);
      encodedTag[i] = (tag & (0xFF << pos)) >> pos;
    }
    // TODO: add tag class
    //encodedTag[0] |= 0x40;
    return encodedTag;
  }

  /// Returns decoded BER-TLV encoded tag and number of bytes encoded tag took.
  /// throws [TLVError] if [encodedTag] is empty or if tag encoding is invalid.
  static DecodedTag decodeTag(final Uint8List encodedTag) {
    if (encodedTag.isEmpty) {
      throw TLVError("Can't decode empty encodedTag");
    }

    int tag = 0;
    int b = encodedTag[0];
    int offset = 1;
    switch (b & 0x1F) {
      case 0x1F:
        {
          if (offset >= encodedTag.length) {
            throw TLVError("Invalid encoded tag");
          }

          tag = b; // We store the first byte including LHS nibble
          b = encodedTag[offset];
          offset += 1;

          while ((b & 0x80) == 0x80) {
            if (offset >= encodedTag.length) {
              throw TLVError("Invalid encoded tag");
            }

            tag <<= 8;
            tag |= b & 0x7F;
            b = encodedTag[offset];
            offset += 1;
          }

          tag <<= 8;
          tag |= b & 0x7F; // Byte with MSB set is last byte of tag.
        }
        break;
      default:
        tag = b;
    }

    return DecodedTag(tag, offset);
  }

  /// Returns BER encoded length
  /// [length] can't be negative and max value can be 16 777 215.
  static Uint8List encodeLength(int length) {
    if (length < 0 || length > 0xFFFFFF) {
      throw TLVError("Can't encode negative or greater than 16 777 215 length");
    }

    var byteCount   = Utils.byteCount(length);
    var encodedLength = Uint8List(byteCount + (byteCount == 0 /*length=0*/ || length >= 0x80 ? 1 : 0));
    if (length < 0x80) {
      // short form
      encodedLength[0] = length;
    } else {
      // long form
      assert(byteCount < 3);
      encodedLength[0] = byteCount | 0x80;
      for (int i = 0 ; i < byteCount; i++) {
        final pos = 8 * (byteCount - i - 1);
        encodedLength[i + 1] = (length & (0xFF << pos)) >> pos; // encode in big endian order
      }
    }
    return encodedLength;
  }

  /// Returns decoded BER encoded length and number of bytes encoded length took.
  /// Max length to decode is 0xFFFFFF
  /// throws [TLVError] if [encodedLength] is empty or if tag encoding is invalid.
  static DecodedLen decodeLength(Uint8List encodedLength) {
    if (encodedLength.isEmpty) {
      throw TLVError("Can't decode empty encodedLength");
    }

    int length = encodedLength[0] & 0xff;
    int byteCount = 1;
    if ((length & 0x80) == 0x80) {
      // long form
      byteCount = length & 0x7f;
      if (byteCount > 3) {
        throw TLVError("Encoded length is too big");
      }

      length = 0;
      byteCount = 1 + byteCount;
      if (byteCount > encodedLength.length) {
        throw TLVError("Invalid encoded length");
      }

      for (int i = 1; i < byteCount; i++) {
        length = length * 0x100 + (encodedLength[i] & 0xff);
      }
    }

    return DecodedLen(length, byteCount);
  }
}
