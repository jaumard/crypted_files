import 'dart:convert';
import 'dart:io';

import 'package:libsodium/libsodium.dart';

mixin EncryptionMetadata {
  File metadataFile;

  void _writeMetadataSync(Map<String, dynamic> metadata) {
    return metadataFile.writeAsStringSync(jsonEncode(metadata), flush: true, mode: FileMode.writeOnly);
  }

  Map<String, dynamic> _readMetadataSync() {
    return jsonDecode(metadataFile.readAsStringSync());
  }

  Future<void> _writeMetadata(Map<String, dynamic> metadata) {
    return metadataFile.writeAsString(jsonEncode(metadata), flush: true, mode: FileMode.writeOnly);
  }

  Future<Map<String, dynamic>> _readMetadata() {
    return metadataFile.readAsString().then((json) => jsonDecode(json));
  }
}

abstract class Encryption {
  Future<Digest> encrypt(List<int> content);

  Future<Digest> decrypt(List<int> content);

  Digest encryptSync(List<int> content);

  Digest decryptSync(List<int> content);
}

class SecretBoxEncryption extends Encryption with EncryptionMetadata {
  static const String metadataKey = 'key';
  static const String metadataLength = 'length';

  final SecretBox secretBox = SecretBox();
  final String _passPhrase;
  final Encoding encoding;

  @override
  File metadataFile;

  SecretBoxEncryption(this._passPhrase, {this.encoding: utf8});

  @override
  Future<Digest> decrypt(List<int> content) async {
    final metadata = await _readMetadata();
    return secretBox.openEasy(metadata[metadataLength], content, encoding.encode(_passPhrase), metadata[metadataKey].cast<int>());
  }

  @override
  Future<Digest> encrypt(List<int> content) async {
    final key = secretBox.keygen();
    await _writeMetadata({metadataKey: key.bytes, metadataLength: content.length});
    return secretBox.easy(content, encoding.encode(_passPhrase), key.bytes);
  }

  @override
  Digest decryptSync(List<int> content) {
    final metadata = _readMetadataSync();
    return secretBox.openEasy(metadata[metadataLength], content, encoding.encode(_passPhrase), metadata[metadataKey].cast<int>());
  }

  @override
  Digest encryptSync(List<int> content) {
    final key = secretBox.keygen();
    _writeMetadataSync({metadataKey: key.bytes, metadataLength: content.length});
    return secretBox.easy(content, encoding.encode(_passPhrase), key.bytes);
  }
}
