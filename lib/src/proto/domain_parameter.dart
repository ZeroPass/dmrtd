//  Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.

enum DomainParameterType {
  None,
  GFP,
  ECP,
}
BigInt p = BigInt.parse('B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371', radix: 16);
int g = int.parse('A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5', radix: 16);


class DomainParameter{
  late int _id;
  late String _name;
  late int _size;
  late DomainParameterType _type;
  late bool _isSupported; //is supported by this library (is in pointycastle)

  DomainParameter({required int id,
    required String name,
    required int size,
    required DomainParameterType type,
    required bool isSupported}):
        _id = id,
        _name = name,
        _size = size,
        _type = type,
        _isSupported = isSupported;

  int get id => _id;

  @override
  String toString() => "DomainParameter(id: $_id, name: $_name, size: $_size, type: $_type, isSupported: $_isSupported)";

  String get name => _name;

  int get size => _size;

  DomainParameterType get type => _type;

  bool get isSupported => _isSupported;

  @override
  bool operator == (Object other) {
    if (other is! DomainParameter) {
      return false;
    }
    return _id == other.id;
  }
}
// Specified in section 9.5.1 of ICAO 9303 p11
Map<int, DomainParameter> ICAO_DOMAIN_PARAMETERS = {
  0   : DomainParameter(id: 0,   name: "1024-bit MODP Group with 160-bit Prime Order Subgroup",   size: 1024, type: DomainParameterType.GFP, isSupported: false ),
  1   : DomainParameter(id: 1,   name: "2048-bit MODP Group with 224-bit Prime Order Subgroup",   size: 2048, type: DomainParameterType.GFP, isSupported: false ),
  2   : DomainParameter(id: 2,   name: "2048-bit MODP Group with 256-bit Prime Order Subgroup",   size: 2048, type: DomainParameterType.GFP, isSupported: false ),
  8   : DomainParameter(id: 8,   name: "NIST P-192 (secp192r1)",                                  size: 192,  type: DomainParameterType.ECP, isSupported: false ),
  9   : DomainParameter(id: 9,   name: "BrainpoolP192r1",                                         size: 192,  type: DomainParameterType.ECP, isSupported: false ),
  10  : DomainParameter(id: 10,  name: "NIST P-224 (secp224r1)",                                  size: 224,  type: DomainParameterType.ECP, isSupported: false ),
  11  : DomainParameter(id: 11,  name: "BrainpoolP224r1",                                         size: 224,  type: DomainParameterType.ECP, isSupported: false ),
  12  : DomainParameter(id: 12,  name: "NIST P-256 (secp256r1)",                                  size: 256,  type: DomainParameterType.ECP, isSupported: true  ),
  13  : DomainParameter(id: 13,  name: "BrainpoolP256r1",                                         size: 256,  type: DomainParameterType.ECP, isSupported: false ),
  14  : DomainParameter(id: 14,  name: "BrainpoolP320r1",                                         size: 320,  type: DomainParameterType.ECP, isSupported: false ),
  15  : DomainParameter(id: 15,  name: "NIST P-384 (secp384r1)",                                  size: 384,  type: DomainParameterType.ECP, isSupported: false ),
  16  : DomainParameter(id: 16,  name: "BrainpoolP384r1",                                         size: 384,  type: DomainParameterType.ECP, isSupported: false ),
  17  : DomainParameter(id: 17,  name: "BrainpoolP512r1",                                         size: 512,  type: DomainParameterType.ECP, isSupported: false ),
  18  : DomainParameter(id: 18,  name: "NIST P-521 (secp521r1)",                                  size: 521,  type: DomainParameterType.ECP, isSupported: false )
};