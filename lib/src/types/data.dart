import 'dart:ffi';
import 'dart:typed_data';


///
/// Class repesents one Data Row in a Data Field. MRTD additional data
/// is stored in communication messages.
/// Structure:
///   [Tag, Length, Value]
///

class DataRowException implements Exception {
  final String message;
  DataRowException(this.message);
  @override
  String toString() => "DataRowException: $message";
}

class DataRow {
  late int tag;
  late int length;
  late Uint8List value;

  DataRow({required int tag, required Uint8List value}) {
    this.tag = tag;
    this.value = value;
    // Calculate the length of `value` and convert it to a hexadecimal string.
    this.length = value != null ? value.length : 0;
  }

  //convert all members to a hexadecimal Uint8List
  Uint8List toList() {
    // Create a Uint8List with a length of 4 + length of `value`.
    final bytes = value != null ? Uint8List(2 + value.length) : Uint8List(2);
    bytes[0] = tag;
    bytes[1] = length;
    // Set the third and fourth bytes to `value`.
    if (value != null)
      bytes.setRange(2, 2 + value.length, value);
    return bytes;
  }

  //print Hexadecimal Uint8List
  String printHex() {
    Uint8List bytes = this.toList();
    return bytes.map((byte) => '0x' + byte.toRadixString(16).padLeft(2, '0') + " ").join();
  }
}



///
/// Class repesents one entire data set in a Data Field. MRTD additional data
/// is stored in commmunication messages.
/// Structure:
///   [Tag, Length, Value]
///   [Tag, Length, Value]
///   [Tag, Length, Value]
///   ...
///
///  toList() returns all data rows as a Uint8List
///  [Tag, Length, Value] + [Tag, Length, Value] + [Tag, Length, Value]

class DataSet {
  List<DataRow> rows = [];

  void addRawRow({required int tag, required Uint8List value}) {
    rows.add(DataRow(tag: tag, value: value));
  }

  void addRow({required DataRow row}){
    rows.add(row);
  }

  ///it returns chunk of all data rows as a Uint8List
  Uint8List toList(){
    var b = BytesBuilder();
    //final bytes = Uint8List(rows.length);
    for (DataRow row in rows) {
      b.add(row.toList());
    }
    return b.toBytes();
  }

  void clear() {
    rows.clear();
  }

}


