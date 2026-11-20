import 'package:test/test.dart';

import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/extensions.dart';

// SecurityInfos (DER) used below.
// PACEInfo: id-PACE-ECDH-GM-AES-CBC-CMAC-128, version 2, parameterId 13 (brainpoolP256r1)
const paceInfo = "3012060A04007F0007020204020202010202010D";
// ChipAuthenticationInfo: id-CA-ECDH-AES-CBC-CMAC-128, version 2
const caInfo = "300F060A04007F00070202030202020102";
// TerminalAuthenticationInfo: id-TA, version 2
const taInfo = "300D060804007F0007020202020102";
// PACEDomainParameterInfo: id-PACE-ECDH-GM, AlgorithmIdentifier { id-ecPublicKey }
const paceDomainParameterInfo = "3016060904007F000702020402300906072A8648CE3D0201";

void main() {
  test('EF.CardAccess with PACEInfo only', () {
    final ef = EfCardAccess.fromBytes("3114$paceInfo".parseHex());
    expect(ef.isPaceInfoSet, true);
    expect(ef.paceInfo!.version, 2);
    expect(ef.paceInfo!.parameterId, 13);
  });

  test('EF.CardAccess with other SecurityInfos before PACEInfo', () {
    // As on German ID cards: TerminalAuthenticationInfo and ChipAuthenticationInfo come first.
    final ef = EfCardAccess.fromBytes(
        "314C$taInfo$caInfo$paceDomainParameterInfo$paceInfo".parseHex());
    expect(ef.isPaceInfoSet, true);
    expect(ef.paceInfo!.version, 2);
    expect(ef.paceInfo!.parameterId, 13);
  });

  test('EF.CardAccess without PACEInfo', () {
    expect(() => EfCardAccess.fromBytes("3120$taInfo$caInfo".parseHex()),
        throwsA(isA<EfParseError>()));
  });
}
