// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: constant_identifier_names

import 'dart:core';
import 'dart:convert';
import 'dart:typed_data';
import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/extensions.dart';

import 'dg.dart';

enum ImageType { jpeg, jpeg2000 }

class EfDG2 extends DataGroup {
  static const FID = 0x0102;
  static const SFI = 0x02;
  static const TAG = DgTag(0x75);

  static const BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG = 0x7F61;
  static const BIOMETRIC_INFORMATION_TEMPLATE_TAG = 0x7F60;

  static const BIOMETRIC_HEADER_TEMPLATE_BASE_TAG = 0xA1;

  static const BIOMETRIC_DATA_BLOCK_TAG = 0x5F2E;
  static const BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG = 0x7F2E;

  static const BIOMETRIC_INFORMATION_COUNT_TAG = 0x02;
  static const SMT_TAG = 0x7D;
  static const VERSION_NUMBER = 0x30313000;

  EfDG2.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  int get fid => FID;

  @override
  int get sfi => SFI;

  @override
  int get tag => TAG.value;

  late int versionNumber;
  late int lengthOfRecord;
  late int numberOfFacialImages;
  late int facialRecordDataLength;
  late int nrFeaturePoints;
  late int gender;
  late int eyeColor;
  late int hairColor;
  late int featureMask;
  late int expression;
  late int poseAngle;
  late int poseAngleUncertainty;
  late int faceImageType;
  late int imageWidth;
  late int imageHeight;
  late int imageColorSpace;
  late int sourceType;
  late int deviceType;
  late int quality;

  Uint8List? imageData;
  int? _imageDataType;

  ImageType? get imageType {
    if (_imageDataType == null) return null;

    return _imageDataType == 0 ? ImageType.jpeg : ImageType.jpeg2000;
  }

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

    if (bict.tag.value != BIOMETRIC_INFORMATION_COUNT_TAG) {
      throw EfParseError(
          "Invalid object tag=${bict.tag.value.hex()}, expected tag=$BIOMETRIC_INFORMATION_COUNT_TAG");
    }

    int bitCount = (bict.value[0] & 0xFF);

    for (var i = 0; i < bitCount; i++) {
      _readBIT(bigt.value.sublist(bict.encodedLen), i);
    }
  }

  _readBIT(Uint8List stream, int index) {
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

      _readBiometricDataBlock(sbh);
    }
  }

  //TODO Reads a biometric information template protected with secure messaging.
  _readStaticallyProtectedBIT() {}

  List<DecodedTV> _readBHT(Uint8List stream) {
    final bht = TLV.decode(stream);

    if (bht.tag.value != BIOMETRIC_HEADER_TEMPLATE_BASE_TAG) {
      throw EfParseError(
          "Invalid object tag=${bht.tag.value.hex()}, expected tag=${BIOMETRIC_INFORMATION_TEMPLATE_TAG}");
    }

    int bhtLength = stream.length;
    int bytesRead = bht.encodedLen;
    var elements = <DecodedTV>[];
    while (bytesRead < bhtLength) {
      final tlv = TLV.decode(stream.sublist(bytesRead));
      bytesRead += tlv.encodedLen;
      elements.add(tlv);
    }

    return elements;
  }

  _readBiometricDataBlock(List<DecodedTV> sbh) {
    var firstBlock = sbh.first;
    if (firstBlock.tag.value != BIOMETRIC_DATA_BLOCK_TAG &&
        firstBlock.tag.value != BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG) {
      throw EfParseError(
          "Invalid object tag=${firstBlock.tag.value.hex()}, expected tag=$BIOMETRIC_DATA_BLOCK_TAG or $BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG ");
    }

    var data = firstBlock.value;
    if (data[0] != 0x46 &&
        data[1] != 0x41 &&
        data[2] != 0x43 &&
        data[3] != 0x00) {
      throw EfParseError("Biometric data block is invalid");
    }

    var offset = 4;

    versionNumber = _extractContent(data, start: offset, end: offset + 4);

    if (versionNumber != VERSION_NUMBER) {
      throw EfParseError("Version of Biometric data is not valid");
    }

    offset += 4;

    lengthOfRecord = _extractContent(data, start: offset, end: offset + 4);
    offset += 4;

    numberOfFacialImages =
        _extractContent(data, start: offset, end: offset + 2);
    offset += 2;

    facialRecordDataLength =
        _extractContent(data, start: offset, end: offset + 4);
    offset += 4;

    nrFeaturePoints = _extractContent(data, start: offset, end: offset + 2);
    offset += 2;

    gender = _extractContent(data, start: offset, end: offset + 1);
    offset += 1;

    eyeColor = _extractContent(data, start: offset, end: offset + 1);
    offset += 1;

    hairColor = _extractContent(data, start: offset, end: offset + 1);
    offset += 1;

    featureMask = _extractContent(data, start: offset, end: offset + 3);
    offset += 3;

    expression = _extractContent(data, start: offset, end: offset + 2);
    offset += 2;

    poseAngle = _extractContent(data, start: offset, end: offset + 3);
    offset += 3;

    poseAngleUncertainty =
        _extractContent(data, start: offset, end: offset + 3);
    offset += 3;

    // Features (not handled). There shouldn't be any but if for some reason there were,
    // then we are going to skip over them
    // The Feature block is 8 bytes
    offset += nrFeaturePoints * 8;

    faceImageType = _extractContent(data, start: offset, end: offset + 1);
    offset += 1;

    _imageDataType = _extractContent(data, start: offset, end: offset + 1);
    offset += 1;

    imageWidth = _extractContent(data, start: offset, end: offset + 2);
    offset += 2;

    imageHeight = _extractContent(data, start: offset, end: offset + 2);
    offset += 2;

    imageColorSpace = _extractContent(data, start: offset, end: offset + 1);
    offset += 1;

    sourceType = _extractContent(data, start: offset, end: offset + 1);
    offset += 1;

    deviceType = _extractContent(data, start: offset, end: offset + 2);
    offset += 2;

    quality = _extractContent(data, start: offset, end: offset + 2);
    offset += 2;

    imageData = sbh.first.value.sublist(offset);
  }

  int _extractContent(Uint8List data, {required int start, required int end}) {
    if (end - start == 1) {
      return data.sublist(start, end).buffer.asByteData().getInt8(0);
    } else if (end - start < 4)
      return data.sublist(start, end).buffer.asByteData().getInt16(0);
    // else if(end - start == 4)
    return data.sublist(start, end).buffer.asByteData().getInt32(0);
  }
}
