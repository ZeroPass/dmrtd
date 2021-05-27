import 'package:dmrtd/dmrtd.dart';
import 'package:test/test.dart';

Matcher throwsE<T extends Exception>({required String message}) => allOf(throwsA(TypeMatcher<T>()), throwsA((T e) => e.toString() == message));//"Can't decode empty encodedTag"));

Matcher throwsEfParseError({required String message}) => throwsE<EfParseError>(message: message);
Matcher throwsMRZParseError({required String message}) => throwsE<MRZParseError>(message: message);
Matcher throwsTLVError({required String message}) => throwsE<TLVError>(message: message);



