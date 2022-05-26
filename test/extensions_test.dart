//  Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'package:logging/logging.dart';
import 'package:test/test.dart';
import 'dart:typed_data';

import 'package:dmrtd/src/extension/logging_apis.dart';
import 'package:dmrtd/src/extension/datetime_apis.dart';
import 'package:dmrtd/src/extension/string_apis.dart';
import 'package:dmrtd/src/extension/uint8list_apis.dart';

void main() {

  group('HEX encoding/decoding', () {
    test('Encoding Uint8List to HEX string', () {
      expect( Uint8List.fromList([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).hex(), "000102030405060708090a0b0c0d0e0f112233445566778899aabbccddeeff" );
    });

    test('Decoding Uint8List from HEX string', () {
      expect( "".parseHex() , Uint8List(0) );
      expect( "000102030405060708090A0B0C0D0E0F112233445566778899AABBCCDDEEFF".parseHex() , Uint8List.fromList([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]) );

      // Test exception on prefix invalid char
      expect( () => "0!02".parseHex() , throwsFormatException );
      // Test exception on prefix '0x'
      expect( () => "0x000102030405060708090A0B0C0D0E0F112233445566778899AABBCCDDEEFF".parseHex() , throwsFormatException );
      // Test exception on uneven input
      expect( () => "00102030405060708090A0B0C0D0E0F112233445566778899AABBCCDDEEFF".parseHex() , throwsFormatException );
    });
  });

  group('Base64 encoding/decoding', () {
    // Test vectors from https://tools.ietf.org/html/rfc4648 page 13, part 10. Test vectors
    test('Encoding Uint8List to base64 string', () {
      expect( Uint8List(0).base64() , "");
      expect( Uint8List.fromList("f".codeUnits).base64()      , "Zg=="     );
      expect( Uint8List.fromList("fo".codeUnits).base64()     , "Zm8="     );
      expect( Uint8List.fromList("foo".codeUnits).base64()    , "Zm9v"     );
      expect( Uint8List.fromList("foob".codeUnits).base64()   , "Zm9vYg==" );
      expect( Uint8List.fromList("fooba".codeUnits).base64()  , "Zm9vYmE=" );
      expect( Uint8List.fromList("foobar".codeUnits).base64() , "Zm9vYmFy" );
      expect( Uint8List.fromList([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD]).base64(), "AAECAwQFBgcICQoLDA0ODxEiM0RVZneImaq7zN0=" );
      expect( Uint8List.fromList([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]).base64(), "AAECAwQFBgcICQoLDA0ODxEiM0RVZneImaq7zN3u" );
      expect( Uint8List.fromList([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).base64(), "AAECAwQFBgcICQoLDA0ODxEiM0RVZneImaq7zN3u/w==" );
    });

    test('Decoding Uint8List from base64 string', () {
      expect( "".parseBase64()                               , Uint8List(0) );
      expect( String.fromCharCodes("Zg==".parseBase64())     , "f"          );
      expect( String.fromCharCodes("Zm8=".parseBase64())     , "fo"         );
      expect( String.fromCharCodes("Zm9v".parseBase64())     , "foo"        );
      expect( String.fromCharCodes("Zm9vYg==".parseBase64()) , "foob"       );
      expect( String.fromCharCodes("Zm9vYmE=".parseBase64()) , "fooba"      );
      expect( String.fromCharCodes("Zm9vYmFy".parseBase64()) , "foobar"     );
      expect( "AAECAwQFBgcICQoLDA0ODxEiM0RVZneImaq7zN0=".parseBase64()     , Uint8List.fromList([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD])             );
      expect( "AAECAwQFBgcICQoLDA0ODxEiM0RVZneImaq7zN3u".parseBase64()     , Uint8List.fromList([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE])       );
      expect( "AAECAwQFBgcICQoLDA0ODxEiM0RVZneImaq7zN3u/w==".parseBase64() , Uint8List.fromList([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]) );

      // Test FormatException for invalid char
      expect( () => "Z!8=".parseBase64() , throwsFormatException );
      // Test FormatException for invalid length, must be multiple of four
      expect( () => "Zm8".parseBase64() , throwsFormatException );
    });
  });

  group('Date YYMMDD format test', () {
    test('Converting DateTime to YYMMDD format string', () {
      expect( DateTime(1989, 11, 9).formatYYMMDD() , '891109' );
      expect( DateTime(1976, 05, 01).formatYYMMDD(), '760501' );
      expect( DateTime(2000, 02, 15).formatYYMMDD(), '000215' );
      expect( DateTime(2006, 08, 30).formatYYMMDD(), '060830' );
      expect( DateTime(2011, 11, 11).formatYYMMDD(), '111111' );
      expect( DateTime(2012, 12, 12).formatYYMMDD(), '121212' );
    });

    test('Converting DateTime to YYMMDD format string', () {
      expect( '891109'.parseDateYYMMDD() , DateTime(1989, 11, 9)  );
      expect( '760501'.parseDateYYMMDD() , DateTime(1976, 05, 01) );
      expect( '000215'.parseDateYYMMDD() , DateTime(2000, 02, 15) );
      expect( '111111'.parseDateYYMMDD() , DateTime(2011, 11, 11) );
      expect( '121212'.parseDateYYMMDD() , DateTime(2012, 12, 12) );
      expect( '201212'.parseDateYYMMDD() , DateTime(2020, 12, 12) );

      final now = DateTime(DateTime.now().year, DateTime.now().month, DateTime.now().day);
      expect( now.formatYYMMDD().parseDateYYMMDD() , now );

      final nextMonth = DateTime(now.year, now.month + 1, now.day);
      expect( nextMonth.formatYYMMDD().parseDateYYMMDD(), nextMonth );

      final tenFromNow  = DateTime(now.year + 10, now.month, now.day);
      expect( tenFromNow.formatYYMMDD().parseDateYYMMDD(), tenFromNow );

      // 10 years and 6 months from now should wind date back for a century.
      final tenAnd6MonthsFromNow = DateTime(now.year + 10, now.month + 6, now.day);
      final ninetyYearsAgo       = DateTime(now.year - 90, now.month + 6, now.day);
      expect( tenAnd6MonthsFromNow.formatYYMMDD().parseDateYYMMDD(), ninetyYearsAgo );
    });
  });

  group('LogApis tests', () {
    const traceMsg   = 'test trace log msg';
    const verboseMsg = 'test verbose log msg';
    const debugMsg   = 'test debug log msg';
    const infoMsg    = 'test info log msg';
    const warningMsg = 'test warning log msg';
    const errorMsg   = 'test error log msg';
    const shoutMsg   = 'test trace log msg';

    var level = Level.OFF;
    var logMsg = '';
    Logger.root.onRecord.listen((record) {
      level = record.level;
      logMsg = record.message;
    });

    test('Log level helper functions', () {
      Logger.root.level = Level.OFF;
      // Error test
      Logger.root.error(errorMsg);
      expect( logMsg, ''        );
      expect( level , Level.OFF );

      Logger.root.level = Level.SEVERE;
      Logger.root.error(errorMsg);
      expect( logMsg, errorMsg     );
      expect( level,  Level.SEVERE );

       // Debug test
      Logger.root.debug(debugMsg);
      expect( logMsg, errorMsg     );
      expect( level , Level.SEVERE );

      Logger.root.level = Level.FINE;
      Logger.root.debug(debugMsg);
      expect( logMsg, debugMsg   );
      expect( level,  Level.FINE );

      // Verbose test
      Logger.root.verbose(verboseMsg);
      expect( logMsg, debugMsg   );
      expect( level , Level.FINE );

      Logger.root.level = Level.FINER;
      Logger.root.verbose(verboseMsg);
      expect( logMsg, verboseMsg );
      expect( level, Level.FINER );

      // Trace test
      Logger.root.trace(traceMsg);
      expect( logMsg, verboseMsg  );
      expect( level , Level.FINER );

      Logger.root.level = Level.FINEST;
      Logger.root.trace(traceMsg);
      expect( logMsg, traceMsg     );
      expect( level , Level.FINEST );     
    });

    test('Sensitive data log test', () {
      level = Level.OFF;
      logMsg = '';
      Logger.root.level = Level.OFF;
      var log = Logger('test_log');

      var dlog = Logger.detached('detached_test_log');
      dlog.level = Level.OFF;
      var dlevel = Level.OFF;
      var dlogMsg = '';
      dlog.onRecord.listen((record) {
        dlevel  = record.level;
        dlogMsg = record.message;
      });

      // Shout test
      Logger.root.logSensitiveData = false;
      dlog.logSensitiveData = false;
      Logger.root.sdShout(shoutMsg);
      expect( logMsg, ''        );
      expect( level , Level.OFF );

      log.sdShout(shoutMsg);
      expect( logMsg, ''        );
      expect( level , Level.OFF );

      dlog.sdShout(shoutMsg);
      expect( logMsg, ''        );
      expect( level , Level.OFF );

      Logger.root.level = Level.SHOUT;
      dlog.level = Level.SHOUT;
      Logger.root.sdShout(shoutMsg);
      expect( logMsg, ''        );
      expect( level , Level.OFF );

      log.sdShout(shoutMsg);
      expect( logMsg, ''        );
      expect( level , Level.OFF );

      dlog.sdShout(shoutMsg);
      expect( logMsg, ''        );
      expect( level , Level.OFF );

      Logger.root.logSensitiveData = true;
      Logger.root.sdShout(shoutMsg);
      expect( logMsg, shoutMsg    );
      expect( level , Level.SHOUT );

      log.sdShout(shoutMsg);
      expect( logMsg, shoutMsg    );
      expect( level , Level.SHOUT );

      dlog.sdShout(shoutMsg);
      expect( dlogMsg, ''        );
      expect( dlevel , Level.OFF );

      dlog.logSensitiveData = true;
      dlog.sdShout(shoutMsg);
      expect( dlogMsg, shoutMsg     );
      expect( dlevel , Level.SHOUT );

      // Error test
      Logger.root.logSensitiveData = false;
      dlog.logSensitiveData = false;
      Logger.root.sdError(errorMsg);
      expect( logMsg, shoutMsg    );
      expect( level , Level.SHOUT );

      log.sdError(errorMsg);
      expect( logMsg, shoutMsg    );
      expect( level , Level.SHOUT );

      dlog.sdError(errorMsg);
      expect( dlogMsg, shoutMsg    );
      expect( dlevel , Level.SHOUT );

      Logger.root.level = Level.SEVERE;
      dlog.level = Level.SEVERE;
      Logger.root.sdError(errorMsg);
      expect( logMsg, shoutMsg    );
      expect( level , Level.SHOUT );

      log.sdError(errorMsg);
      expect( logMsg, shoutMsg    );
      expect( level , Level.SHOUT );

      dlog.sdError(errorMsg);
      expect( dlogMsg, shoutMsg    );
      expect( dlevel , Level.SHOUT );

      Logger.root.logSensitiveData = true;
      Logger.root.sdError(errorMsg);
      expect( logMsg, errorMsg     );
      expect( level , Level.SEVERE );

      log.sdError(errorMsg);
      expect( logMsg, errorMsg     );
      expect( level , Level.SEVERE );

      dlog.sdError(errorMsg);
      expect( dlogMsg, shoutMsg    );
      expect( dlevel , Level.SHOUT );

      dlog.logSensitiveData = true;
      dlog.sdError(errorMsg);
      expect( dlogMsg, errorMsg     );
      expect( dlevel , Level.SEVERE );

      // Warning test
      Logger.root.logSensitiveData = false;
      dlog.logSensitiveData = false;
      Logger.root.sdWarning(warningMsg);
      expect( logMsg, errorMsg     );
      expect( level , Level.SEVERE );

      log.sdWarning(warningMsg);
      expect( logMsg, errorMsg     );
      expect( level , Level.SEVERE );

      dlog.sdWarning(warningMsg);
      expect( dlogMsg, errorMsg     );
      expect( dlevel , Level.SEVERE );

      Logger.root.level = Level.WARNING;
      dlog.level = Level.WARNING;
      Logger.root.sdWarning(warningMsg);
      expect( logMsg, errorMsg     );
      expect( level , Level.SEVERE );

      log.sdWarning(warningMsg);
      expect( logMsg, errorMsg     );
      expect( level , Level.SEVERE );

      dlog.sdWarning(warningMsg);
      expect( dlogMsg, errorMsg     );
      expect( dlevel , Level.SEVERE );

      Logger.root.logSensitiveData = true;
      Logger.root.sdWarning(warningMsg);
      expect( logMsg, warningMsg    );
      expect( level , Level.WARNING );

      log.sdWarning(warningMsg);
      expect( logMsg, warningMsg    );
      expect( level , Level.WARNING );

      dlog.sdWarning(warningMsg);
      expect( dlogMsg, errorMsg     );
      expect( dlevel , Level.SEVERE );

      dlog.logSensitiveData = true;
      dlog.sdWarning(warningMsg);
      expect( dlogMsg, warningMsg    );
      expect( dlevel , Level.WARNING );

      // Info test
      Logger.root.logSensitiveData = false;
      dlog.logSensitiveData = false;
      Logger.root.sdInfo(infoMsg);
      expect( logMsg, warningMsg    );
      expect( level , Level.WARNING );

      log.sdInfo(infoMsg);
      expect( logMsg, warningMsg    );
      expect( level , Level.WARNING );

      dlog.sdInfo(infoMsg);
      expect( dlogMsg, warningMsg    );
      expect( dlevel , Level.WARNING );

      Logger.root.level = Level.INFO;
      dlog.level = Level.INFO;
      Logger.root.sdInfo(infoMsg);
      expect( logMsg, warningMsg    );
      expect( level , Level.WARNING );

      log.sdInfo(infoMsg);
      expect( logMsg, warningMsg    );
      expect( level , Level.WARNING );

      dlog.sdInfo(infoMsg);
      expect( dlogMsg, warningMsg    );
      expect( dlevel , Level.WARNING );

      Logger.root.logSensitiveData = true;
      Logger.root.sdInfo(infoMsg);
      expect( logMsg, infoMsg    );
      expect( level , Level.INFO );

      log.sdInfo(infoMsg);
      expect( logMsg, infoMsg    );
      expect( level , Level.INFO );

      dlog.sdInfo(infoMsg);
      expect( dlogMsg, warningMsg    );
      expect( dlevel , Level.WARNING );

      dlog.logSensitiveData = true;
      dlog.sdInfo(infoMsg);
      expect( dlogMsg, infoMsg    );
      expect( dlevel , Level.INFO );

      // Debug test
      Logger.root.logSensitiveData = false;
      dlog.logSensitiveData = false;
      Logger.root.sdDebug(debugMsg);
      expect( logMsg, infoMsg    );
      expect( level , Level.INFO );

      log.sdDebug(debugMsg);
      expect( logMsg, infoMsg    );
      expect( level , Level.INFO );

      dlog.sdDebug(debugMsg);
      expect( dlogMsg, infoMsg    );
      expect( dlevel , Level.INFO );

      Logger.root.level = Level.FINE;
      dlog.level = Level.FINE;
      Logger.root.sdDebug(debugMsg);
      expect( logMsg, infoMsg    );
      expect( level , Level.INFO );

      log.sdDebug(debugMsg);
      expect( logMsg, infoMsg    );
      expect( level , Level.INFO );

      dlog.sdDebug(debugMsg);
      expect( dlogMsg, infoMsg    );
      expect( dlevel , Level.INFO );

      Logger.root.logSensitiveData = true;
      Logger.root.sdDebug(debugMsg);
      expect( logMsg, debugMsg   );
      expect( level , Level.FINE );

      log.sdDebug(debugMsg);
      expect( logMsg, debugMsg   );
      expect( level , Level.FINE );

      dlog.sdDebug(debugMsg);
      expect( dlogMsg, infoMsg    );
      expect( dlevel , Level.INFO );

      dlog.logSensitiveData = true;
      dlog.sdDebug(debugMsg);
      expect( dlogMsg, debugMsg   );
      expect( dlevel , Level.FINE );
      
      // Verbose test
      Logger.root.logSensitiveData = false;
      dlog.logSensitiveData = false;
      Logger.root.sdVerbose(verboseMsg);
      expect( logMsg, debugMsg   );
      expect( level , Level.FINE );

      log.sdVerbose(verboseMsg);
      expect( logMsg, debugMsg   );
      expect( level , Level.FINE );

      dlog.sdVerbose(verboseMsg);
      expect( dlogMsg, debugMsg   );
      expect( dlevel , Level.FINE );

      Logger.root.level = Level.FINER;
      dlog.level = Level.FINER;
      Logger.root.sdVerbose(verboseMsg);
      expect( logMsg, debugMsg   );
      expect( level , Level.FINE );

      log.sdVerbose(verboseMsg);
      expect( logMsg, debugMsg   );
      expect( level , Level.FINE );

      dlog.sdVerbose(verboseMsg);
      expect( dlogMsg, debugMsg   );
      expect( dlevel , Level.FINE );

      Logger.root.logSensitiveData = true;
      Logger.root.sdVerbose(verboseMsg);
      expect( logMsg, verboseMsg  );
      expect( level , Level.FINER );

      log.sdVerbose(verboseMsg);
      expect( logMsg, verboseMsg  );
      expect( level , Level.FINER );

      dlog.sdVerbose(verboseMsg);
      expect( dlogMsg, debugMsg   );
      expect( dlevel , Level.FINE );

      dlog.logSensitiveData = true;
      dlog.sdVerbose(verboseMsg);
      expect( dlogMsg, verboseMsg  );
      expect( dlevel , Level.FINER );

      // Trace test
      Logger.root.logSensitiveData = false;
      dlog.logSensitiveData = false;
      Logger.root.sdTrace(traceMsg);
      expect( logMsg, verboseMsg  );
      expect( level , Level.FINER );

      log.sdTrace(traceMsg);
      expect( logMsg, verboseMsg  );
      expect( level , Level.FINER );

      dlog.sdTrace(traceMsg);
      expect( dlogMsg, verboseMsg  );
      expect( dlevel , Level.FINER );

      Logger.root.level = Level.FINEST;
      dlog.level = Level.FINEST;
      Logger.root.sdTrace(traceMsg);
      expect( logMsg, verboseMsg  );
      expect( level , Level.FINER );

      log.sdTrace(traceMsg);
      expect( logMsg, verboseMsg  );
      expect( level , Level.FINER );

      dlog.sdTrace(traceMsg);
      expect( dlogMsg, verboseMsg  );
      expect( dlevel , Level.FINER );

      Logger.root.logSensitiveData = true;
      Logger.root.sdTrace(traceMsg);
      expect( logMsg, traceMsg     );
      expect( level , Level.FINEST );

      log.sdTrace(traceMsg);
      expect( logMsg, traceMsg     );
      expect( level , Level.FINEST );

      dlog.sdTrace(traceMsg);
      expect( dlogMsg, verboseMsg  );
      expect( dlevel , Level.FINER );

      dlog.logSensitiveData = true;
      dlog.sdTrace(traceMsg);
      expect( dlogMsg, traceMsg     );
      expect( dlevel , Level.FINEST );
    });
  });
}