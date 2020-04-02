//  Copyright © 2020 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';
import 'package:meta/meta.dart';

/// Class defines ISO/IEC 7816-4 response APDU
class ResponseAPDU {
    StatusWord _sw;
    Uint8List _data;

    StatusWord get status => _sw;
    Uint8List get data => _data;

    ResponseAPDU(this._sw, this._data);

    ResponseAPDU.fromBytes(final Uint8List apduBytes) {
      if(apduBytes == null) {
        throw ArgumentError.notNull('apduBytes');
      }
      if(apduBytes.length < 2) {
        throw ArgumentError("Invalid raw response APDU length");
      }

      if(apduBytes.length > 2) {
        _data = apduBytes.sublist(0, apduBytes.length - 2);
      }

      _sw = StatusWord.fromBytes(apduBytes, apduBytes.length - 2);
    }

    Uint8List toBytes() => Uint8List.fromList((_data ?? Uint8List(0))  + _sw.toBytes());
    String toString() => '$status data=${_data?.hex()}';
}


/// Class represents trailer status bytes of ISO/IEC 7816-4 response APDU.
class StatusWord {
  // Defined in ISO/IEC 7816-4 Figure 7 - Structural scheme of status bytes
  static const noInformationGiven                = StatusWord(sw1: 0x62, sw2: 0x00);
  static const possibleCorruptedData             = StatusWord(sw1: 0x62, sw2: 0x81);
  static const unexpectedEOF                     = StatusWord(sw1: 0x62, sw2: 0x82);
  static const selectedFileInvalidated           = StatusWord(sw1: 0x62, sw2: 0x83);
  static const wrongFCIFormat                    = StatusWord(sw1: 0x62, sw2: 0x84);
  static const wrongLength                       = StatusWord(sw1: 0x67, sw2: 0x00);
  static const claFunctionNotSupported           = StatusWord(sw1: 0x68, sw2: 0x00);
  static const logicalChannelNotSupported        = StatusWord(sw1: 0x68, sw2: 0x81);
  static const secureMessagingNotSupported       = StatusWord(sw1: 0x68, sw2: 0x82);
  static const commandNotAllowed                 = StatusWord(sw1: 0x69, sw2: 0x00);
  static const incompatibleFileStructureCommand  = StatusWord(sw1: 0x69, sw2: 0x81);
  static const securityStatusNotSatisfied        = StatusWord(sw1: 0x69, sw2: 0x82);
  static const authenticationMethodBlocked       = StatusWord(sw1: 0x69, sw2: 0x83);
  static const referencedDataInvalidated         = StatusWord(sw1: 0x69, sw2: 0x84);
  static const conditionsNotSatisfied            = StatusWord(sw1: 0x69, sw2: 0x85);
  static const commandNotAllowedNoEF             = StatusWord(sw1: 0x69, sw2: 0x86);
  static const smDataMissing                     = StatusWord(sw1: 0x69, sw2: 0x87);
  static const smDataInvalid                     = StatusWord(sw1: 0x69, sw2: 0x88);
  static const wrongParameters                   = StatusWord(sw1: 0x6A, sw2: 0x00);
  static const invalidDataFieldParameters        = StatusWord(sw1: 0x6A, sw2: 0x80);
  static const notSupported                      = StatusWord(sw1: 0x6A, sw2: 0x81);
  static const fileNotFound                      = StatusWord(sw1: 0x6A, sw2: 0x82);
  static const recordNotFound                    = StatusWord(sw1: 0x6A, sw2: 0x83);
  static const notEnoughSpaceInFile              = StatusWord(sw1: 0x6A, sw2: 0x84);
  static const lcInconsistentWithTLV             = StatusWord(sw1: 0x6A, sw2: 0x85);
  static const incorrectParameters               = StatusWord(sw1: 0x6A, sw2: 0x86);
  static const lcInconsistentWithParameters      = StatusWord(sw1: 0x6A, sw2: 0x87);
  static const referencedDataNotFound            = StatusWord(sw1: 0x6A, sw2: 0x88);
  static const wrongParameters2                  = StatusWord(sw1: 0x6B, sw2: 0x00);
  static const invalidInstructionCode            = StatusWord(sw1: 0x6D, sw2: 0x00);
  static const classNotSupported                 = StatusWord(sw1: 0x6E, sw2: 0x00);
  static const noPreciseDiagnostics              = StatusWord(sw1: 0x6F, sw2: 0x00);
  static const success                           = StatusWord(sw1: 0x90, sw2: 0x00);

  static remainingAvailableResponseBytes(int numBytes) { // This is considered as normal status. It's the same as sw=0x9000 - success.
    return StatusWord(sw1: 0x61, sw2: numBytes);
  }

  static leWrongLength(int exactLength) { // Indicates wrong length of Le field. SW2 SW2 indicates the exact length.
    return StatusWord(sw1: 0x6C, sw2: exactLength);
  }

  final int sw1;
  final int sw2;

  int get value {
    return ByteData.view(
      toBytes().buffer
    ).getUint16(0);
  }

  const StatusWord({ @required this.sw1, @required this.sw2 }) :
    assert(sw1 < 256),
    assert(sw2 < 256);

  static StatusWord fromBytes(Uint8List data, [int offset = 0]) {
    if(data.length < 2 ) {
      throw ArgumentError.value(data, "data", "Argument length too small");
    }
    if(data.length - offset < 2) {
      throw ArgumentError.value(offset, "offset", "Argument out of bounds");
    }

    return StatusWord(sw1: data[offset], sw2: data[offset + 1]);
  }

  @override
  bool operator == (rhs) {
    return sw1 == rhs?.sw1 && sw2 == rhs?.sw2;
  }

  @override
  get hashCode => (sw1 << 8) + sw2;

  Uint8List toBytes() {
    return Uint8List.fromList([sw1, sw2]);
  }

  String toString() {
    return 'sw=${value.toRadixString(16)}';
  }

  String description() {
    // ignore: case_expression_type_implements_equals
    switch(this) {
      case noInformationGiven:               return "No information given";
      case possibleCorruptedData:            return "Part of returned data my be corrupted";
      case unexpectedEOF:                    return "End of file reached before reading Le bytes";
      case selectedFileInvalidated:          return "Selected file invalidated";
      case wrongFCIFormat:                   return "FCI not formatted according to 5.1.5";
      case wrongLength:                      return "Wrong length (e.g. wrong Le field)";
      case claFunctionNotSupported:          return "Functions in CLA not support";
      case logicalChannelNotSupported:       return "Logical channel not supported";
      case secureMessagingNotSupported:      return "Secure messaging not supported";
      case commandNotAllowed:                return "Command not allowed";
      case incompatibleFileStructureCommand: return "Command incompatible with file structure";
      case securityStatusNotSatisfied:       return "Security status not satisfied";
      case authenticationMethodBlocked:      return "Authentication method blocked";
      case referencedDataInvalidated:        return "Referenced data invalidated";
      case conditionsNotSatisfied:           return "Conditions of use not satisfied";
      case commandNotAllowedNoEF:            return "Command not allowed (no current EF)";
      case smDataMissing:                    return "Expected SM data objects missing"; // SM - Secure messaging
      case smDataInvalid:                    return "SM data objects incorrect"; // SM - Secure messaging
      case wrongParameters:                  return "Wrong parameter(s) P1-P2";
      case invalidDataFieldParameters:       return "Incorrect parameters in the data field";
      case notSupported:                     return "Function not supported";
      case fileNotFound:                     return "File not found";
      case recordNotFound:                   return "Record not found";
      case notEnoughSpaceInFile:             return "Not enough memory space in the file";
      case lcInconsistentWithTLV:            return "Lc inconsistent with TLV structure";
      case incorrectParameters:              return "Incorrect parameters P1-P2";
      case lcInconsistentWithParameters:     return "Lc inconsistent with P1-P2";
      case referencedDataNotFound:           return "Referenced data not found";
      case wrongParameters2:                 return "Wrong parameter(s) P1-P2";
      case invalidInstructionCode:           return "Instruction code not supported or invalid";
      case classNotSupported:                return "Class not supported";
      case noPreciseDiagnostics:             return "No precise diagnosis";
      case success:                          return "Success";
      default: {
        if(sw1 == 0x6C) { // Wrong length (wrong Le field: 'XX' indicates the exact length).
          return "Wrong length (exact length: $sw2)";
        }
        else if(sw1 == 0x61) { // Normal processing,  SW2 indicates the number of response bytes still available
          return "$sw2 bytes still available";
        }
        return '${value.toRadixString(16)}';
      }
    }
  }
}