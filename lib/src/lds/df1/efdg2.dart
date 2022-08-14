// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: constant_identifier_names

import 'dart:core';
import 'dart:convert';
import 'dart:typed_data';
import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/extensions.dart';

import 'dg.dart';

class EfDG2 extends DataGroup {
  static const FID = 0x0102;
  static const SFI = 0x02;
  static const TAG = DgTag(0x75);

  static const BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG = 0x7F61;
  static const BIOMETRIC_INFORMATION_TEMPLATE_TAG = 0x7F60;

  static const BIOMETRIC_HEADER_TEMPLATE_BASE_TAG = 0xA1;

  static const SMT_TAG = 0x7D;

  EfDG2.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  int get fid => FID;

  @override
  int get sfi => SFI;

  @override
  int get tag => TAG.value;

  Uint8List? photoData;
  int? photoDataType;

  @override
  void parse(Uint8List content) {
    final tlv = TLV.fromBytes(content);
    if (tlv.tag != tag) {
      throw EfParseError(
          "Invalid DG2 tag=${tlv.tag.hex()}, expected tag=${TAG.value.hex()}");
    }

    final data = tlv.value;
    final bigt = TLV.decode(data);

    if (bigt.tag.value != BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG) {
      throw EfParseError(
          "Invalid object tag=${bigt.tag.value.hex()}, expected tag=$BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG");
    }

    final bict = TLV.decode(bigt.value);

    if (bict.tag.value != 0X02) {
      throw EfParseError(
          "Invalid object tag=${bict.tag.value.hex()}, expected tag=${0X02}");
    }

    int bitCount = (bict.value[0] & 0xFF);

    for (var i = 0; i < bitCount; i++) {
      _readBit(bigt.value.sublist(bict.encodedLen), i);
    }
  }

  _readBit(Uint8List stream, int index) {
    final tvl = TLV.decode(stream);

    if (tvl.tag.value != BIOMETRIC_INFORMATION_TEMPLATE_TAG) {
      throw EfParseError(
          "Invalid object tag=${tvl.tag.value.hex()}, expected tag=${BIOMETRIC_INFORMATION_TEMPLATE_TAG}");
    }

    var bht = TLV.decode(tvl.value);

    if (bht.tag.value == SMT_TAG) {
      _readStaticallyProtectedBIT();
    } else if ((bht.tag.value & 0xA0) == 0xA0) {
      var sbh = _readBHT(tvl.value);

      var bdb = _decodeSMTValue();

      var faceInfo = _readBiometricDataBlock(sbh);
    }
  }

  _readStaticallyProtectedBIT() {}

  List<DecodedTV> _readBHT(Uint8List stream) {
    final bht = TLV.decode(stream);
    int bhtLength = stream.length;
    int bytesRead = bht.encodedLen;
    var elements = <DecodedTV>[];
    while (bytesRead < bhtLength) {
      final tlv = TLV.decode(stream.sublist(bytesRead));
      bytesRead += tlv.encodedLen;
      elements.add(tlv);
    }

    return elements;
    // const expectedBHTTag =
    //     (BIOMETRIC_HEADER_TEMPLATE_BASE_TAG /* + index */) & 0xFF;
    // if (tvl.tag.value != expectedBHTTag) {
    //   throw EfParseError(
    //       "Invalid object tag=${tvl.tag.value.hex()}, expected tag=${BIOMETRIC_INFORMATION_TEMPLATE_TAG}");
    // }

    // var bht = TLV.decode(tvl.value);
  }

  _decodeSMTValue() {}

  _readBiometricDataBlock(List<DecodedTV> sbh) {
    final tlv = TLV.decode(sbh.first.value);

    var data = sbh.first.value;

    if (data[0] != 0x46 &&
        data[1] != 0x41 &&
        data[2] != 0x43 &&
        data[3] != 0x00) {
      throw EfParseError("biometric data block is invalid");
    }

    var offset = 4;
    // versionNumber = binToInt(data[offset..<offset+4])
    offset += 4;
    // lengthOfRecord = binToInt(data[offset..<offset+4])
    offset += 4;
    // numberOfFacialImages = binToInt(data[offset..<offset+2])
    offset += 2;

    // facialRecordDataLength = binToInt(data[offset..<offset+4])
    offset += 4;
    var nrFeaturePoints =
        data.sublist(offset, offset + 2).buffer.asByteData().getInt16(0);
    offset += 2;
    // gender = binToInt(data[offset..<offset+1])
    offset += 1;
    // eyeColor = binToInt(data[offset..<offset+1])
    offset += 1;
    // hairColor = binToInt(data[offset..<offset+1])
    offset += 1;
    // featureMask = binToInt(data[offset..<offset+3])
    offset += 3;
    // expression = binToInt(data[offset..<offset+2])
    offset += 2;
    // poseAngle = binToInt(data[offset..<offset+3])
    offset += 3;
    // poseAngleUncertainty = binToInt(data[offset..<offset+3])
    offset += 3;

    // Features (not handled). There shouldn't be any but if for some reason there were,
    // then we are going to skip over them
    // The Feature block is 8 bytes
    offset += nrFeaturePoints * 8;

    // faceImageType = binToInt(data[offset..<offset+1])
    offset += 1;
    // imageDataType = binToInt(data[offset..<offset+1])
    photoDataType =
        data.sublist(offset, offset + 1).buffer.asByteData().getInt8(0);
    offset += 1;
    // imageWidth = binToInt(data[offset..<offset+2])
    offset += 2;
    // imageHeight = binToInt(data[offset..<offset+2])
    offset += 2;
    // imageColorSpace = binToInt(data[offset..<offset+1])
    offset += 1;
    // sourceType = binToInt(data[offset..<offset+1])
    offset += 1;
    // deviceType = binToInt(data[offset..<offset+2])
    offset += 2;
    // quality = binToInt(data[offset..<offset+2])
    offset += 2;

    photoData = sbh.first.value.sublist(offset);

    // final image = TLV.decode(photoData);

    // var imageDataHex = photoData.hex();
    // final imageHex = image.value.hex();
  }
}
