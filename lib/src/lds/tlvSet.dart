// Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.

import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';
import 'package:logging/logging.dart';

import './tlv.dart';

class TLVSetrror implements Exception {
  final String message;
  TLVSetrror(this.message);
  @override
  String toString() => message;
}

///
/// Class represents BER-TLV encoding/decoding functions in a set.
/// A set is a collection of TLV objects.
/// The order of TLV objects in a set is significant.
///
class TLVSet {
  List<TLV> _tlvs;
  static final _log = Logger("TLVSet");

  // Standard Constructor
  TLVSet({List<TLV>? tlvs}):
          this._tlvs = tlvs ?? List<TLV>.empty(growable: true);

  // Factory Constructor
  factory TLVSet.decode({required Uint8List encodedData}) {
    List<TLV> tlvs = [];
    int offset = 0;
    while (offset < encodedData.length) {
      try {
        DecodedTV decodedTV = TLV.decode(encodedData.sublist(offset));
        tlvs.add(TLV(decodedTV.tag.value, decodedTV.value));
        offset += decodedTV.encodedLen;
      } catch (e) {
        _log.error("Decoding error at offset $offset: $e");
        break;
      }
    }
    return TLVSet(tlvs: tlvs);
  }

  void add(TLV tlv) {
    _tlvs.add(tlv);
  }

  Uint8List toBytes() {
    List<int> allBytes = [];
    for (var tlv in _tlvs) {
      allBytes.addAll(tlv.toBytes());
    }
    return Uint8List.fromList(allBytes);
  }

  int get length => _tlvs.length;

  TLV at({required int index}) {
    if (index < 0 || index >= _tlvs.length) {
      _log.error("Index out of bounds");
      throw TLVError("Index out of bounds");
    }
    return _tlvs[index];
  }

  List<TLV> get all => _tlvs;
}