//  Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';

/// Class defines ISO/IEC 7816-4 response APDU
class ResponseAPDU {
  late StatusWord _sw;
  Uint8List? _data;

  StatusWord get status => _sw;
  Uint8List? get data => _data;

  ResponseAPDU(this._sw, this._data);

  ResponseAPDU.fromBytes(final Uint8List apduBytes) {
    if(apduBytes.length < 2) {
      throw ArgumentError("Invalid raw response APDU length");
    }

    if(apduBytes.length > 2) {
      _data = apduBytes.sublist(0, apduBytes.length - 2);
    }

    _sw = StatusWord.fromBytes(apduBytes, apduBytes.length - 2);
  }

  Uint8List toBytes() => Uint8List.fromList((_data ?? Uint8List(0))  + _sw.toBytes());

  @override
  String toString() => '$status data=${_data?.hex()}';
}

/// Class represents trailer status bytes of ISO/IEC 7816-4 response APDU.
class StatusWord {
  final int sw1;
  final int sw2;

  // Defined in ISO/IEC 7816-4 Figure 7 - Structural scheme of status bytes

  // Warnings
  static const noInformationGiven                = StatusWord(sw1: 0x62, sw2: 0x00);
  static const possibleCorruptedData             = StatusWord(sw1: 0x62, sw2: 0x81);
  static const unexpectedEOF                     = StatusWord(sw1: 0x62, sw2: 0x82);
  static const selectedFileInvalidated           = StatusWord(sw1: 0x62, sw2: 0x83);
  static const wrongFCIFormat                    = StatusWord(sw1: 0x62, sw2: 0x84);

  // Errors
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
  static const int sw1WrongLengthWithExactLength = 0x6C; // An error indicating wrong length (wrong Le field), sw2 indicates the exact length

  // Normal processing - success
  static const success                           = StatusWord(sw1: 0x90, sw2: 0x00);
  static const int sw1SuccessWithRemainingBytes  = 0x61; // This is considered as normal status e.g. success.
                                                         // SW2 indicates a number of extra data bytes still available.
                                                         // Can be returned by GET RESPONSE command (ISO 7816-4 section 7)

  static remainingAvailableResponseBytes(int numBytes) {
    return StatusWord(sw1: sw1SuccessWithRemainingBytes, sw2: numBytes); // Normal execution
  }

  static leWrongLength(int exactLength) { // Indicates wrong length of Le field. The SW2 indicates the exact length.
    return StatusWord(sw1: sw1WrongLengthWithExactLength, sw2: exactLength);
  }

  int get value => (sw1 << 8) + sw2;

  const StatusWord({ required this.sw1, required this.sw2 }) :
    assert(sw1 >= 0 && sw1 < 256),
    assert(sw2 >= 0 && sw2 < 256);

  static StatusWord fromBytes(Uint8List data, [int offset = 0]) {
    if(data.length < 2 ) {
      throw ArgumentError.value(data, "data", "Argument length too small");
    }
    if(data.length - offset < 2) {
      throw ArgumentError.value(offset, "offset", "Argument out of bounds");
    }

    return StatusWord(sw1: data[offset], sw2: data[offset + 1]);
  }

  bool isSuccess() {
    return this == success ||
           sw1 == sw1SuccessWithRemainingBytes;
  }

  bool isWarning() {
    return sw1 >= 0x62 && sw1 <= 0x63;
  }

  bool isError() {
    return sw1 >= 0x64 && sw1 != 0x90;
  }

  @override
  bool operator == (covariant StatusWord other) {
    return sw1 == other.sw1 && sw2 == other.sw2;
  }

  @override
  int get hashCode => value;

  Uint8List toBytes() {
    return Uint8List.fromList([sw1, sw2]);
  }

  @override
  String toString() {
    return 'sw=${value.hex()}';
  }

  String description() {
         if (this == noInformationGiven)               { return "No information given";                         }
    else if (this == possibleCorruptedData)            { return "Part of returned data my be corrupted";        }
    else if (this == unexpectedEOF)                    { return "End of file reached before reading Le bytes";  }
    else if (this == selectedFileInvalidated)          { return "Selected file invalidated";                    }
    else if (this == wrongFCIFormat)                   { return "FCI not formatted according to 5.1.5";         }
    else if (this == wrongLength)                      { return "Wrong length (e.g. wrong Le field)";           }
    else if (this == claFunctionNotSupported)          { return "Functions in CLA not support";                 }
    else if (this == logicalChannelNotSupported)       { return "Logical channel not supported";                }
    else if (this == secureMessagingNotSupported)      { return "Secure messaging not supported";               }
    else if (this == commandNotAllowed)                { return "Command not allowed";                          }
    else if (this == incompatibleFileStructureCommand) { return "Command incompatible with file structure";     }
    else if (this == securityStatusNotSatisfied)       { return "Security status not satisfied";                }
    else if (this == authenticationMethodBlocked)      { return "Authentication method blocked";                }
    else if (this == referencedDataInvalidated)        { return "Referenced data invalidated";                  }
    else if (this == conditionsNotSatisfied)           { return "Conditions of use not satisfied";              }
    else if (this == commandNotAllowedNoEF)            { return "Command not allowed (no current EF)";          }
    else if (this == smDataMissing)                    { return "Expected SM data objects missing";             } // SM - Secure messaging
    else if (this == smDataInvalid)                    { return "SM data objects incorrect";                    } // SM - Secure messaging
    else if (this == wrongParameters)                  { return "Wrong parameter(s) P1-P2";                     }
    else if (this == invalidDataFieldParameters)       { return "Incorrect parameters in the data field";       }
    else if (this == notSupported)                     { return "Function not supported";                       }
    else if (this == fileNotFound)                     { return "File not found";                               }
    else if (this == recordNotFound)                   { return "Record not found";                             }
    else if (this == notEnoughSpaceInFile)             { return "Not enough memory space in the file";          }
    else if (this == lcInconsistentWithTLV)            { return "Lc inconsistent with TLV structure";           }
    else if (this == incorrectParameters)              { return "Incorrect parameters P1-P2";                   }
    else if (this == lcInconsistentWithParameters)     { return "Lc inconsistent with P1-P2";                   }
    else if (this == referencedDataNotFound)           { return "Referenced data not found";                    }
    else if (this == wrongParameters2)                 { return "Wrong parameter(s) P1-P2";                     }
    else if (this == invalidInstructionCode)           { return "Instruction code not supported or invalid";    }
    else if (this == classNotSupported)                { return "Class not supported";                          }
    else if (this == noPreciseDiagnostics)             { return "No precise diagnosis";                         }
    else if (this == success)                          { return "Success";                                      }
    else {
      if(sw1 == sw1WrongLengthWithExactLength) { // Wrong length (wrong Le field: 'XX' indicates the exact length).
        return "Wrong length (exact length: $sw2)";
      }
      else if(sw1 == sw1SuccessWithRemainingBytes) { // SW2 indicates the number of response bytes still available
        return "$sw2 byte(s) are still available";
      }
      return toString();
    }
  }
}