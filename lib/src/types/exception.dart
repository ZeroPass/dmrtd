// Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.

class DMRTDException implements Exception {
  final String message;
  String exceptionName = 'DMRTDException';

  DMRTDException(this.message);
  @override
  String toString() {
    String result = 'ASN1ObjectIdentifierException';
    if (message is String) return '$exceptionName: $message';
    return result;
  }
}