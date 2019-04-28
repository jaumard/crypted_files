import 'dart:convert';
import 'dart:io';

import 'package:libsodium/libsodium.dart';

import 'encryption.dart';

class EncryptedFile {
  static const String metadataKey = 'key';
  static const String metadataLength = 'length';
  final String path;
  final String binaryFolder;
  final File metadataFile;

  EncryptedFile(this.path, {String this.binaryFolder}) : metadataFile = File('$path.metadata') {
    sodiumInit(libPath: binaryFolder);
  }

  Future<bool> exists() {
    return File(path).exists();
  }

  bool existsSync() {
    return File(path).existsSync();
  }

  String readAsStringSync(Encryption encryption, {Encoding encoding: utf8}) {
    final file = File(path);
    if (file.existsSync()) {
      if (encryption is EncryptionMetadata) {
        (encryption as EncryptionMetadata).metadataFile = metadataFile;
      }
      final content = file.readAsBytesSync();
      final clearContent = encryption.decryptSync(content);
      return encoding.decode(clearContent.bytes);
    }

    throw StateError('$path doesn\'t exist');
  }

  List<int> readAsBytesSync(Encryption encryption) {
    final file = File(path);
    if (file.existsSync()) {
      if (encryption is EncryptionMetadata) {
        (encryption as EncryptionMetadata).metadataFile = metadataFile;
      }
      final content = file.readAsBytesSync();
      final clearContent = encryption.decryptSync(content);
      return clearContent.bytes;
    }
    throw StateError('$path doesn\'t exist');
  }

  void writeAsStringSync(
    String content,
    Encryption encryption, {
    Encoding encoding: utf8,
    bool flush: false,
  }) {
    if (encryption is EncryptionMetadata) {
      (encryption as EncryptionMetadata).metadataFile = metadataFile;
    }
    final file = File(path);
    final contentBytes = encoding.encode(content);
    final digest = encryption.encryptSync(contentBytes);
    return file.writeAsBytesSync(digest.bytes, flush: flush, mode: FileMode.writeOnly);
  }

  void writeAsBytesSync(
    List<int> content,
    Encryption encryption, {
    bool flush: false,
  }) {
    if (encryption is EncryptionMetadata) {
      (encryption as EncryptionMetadata).metadataFile = metadataFile;
    }
    final file = File(path);
    final digest = encryption.encryptSync(content);
    return file.writeAsBytesSync(digest.bytes, flush: flush, mode: FileMode.writeOnly);
  }

  Future<String> readAsString(Encryption encryption, {Encoding encoding: utf8}) async {
    final file = File(path);
    if (await file.exists()) {
      if (encryption is EncryptionMetadata) {
        (encryption as EncryptionMetadata).metadataFile = metadataFile;
      }
      final content = await file.readAsBytes();
      final clearContent = await encryption.decrypt(content);
      return encoding.decode(clearContent.bytes);
    }

    throw StateError('$path doesn\'t exist');
  }

  Future<List<int>> readAsBytes(Encryption encryption) async {
    final file = File(path);
    if (await file.exists()) {
      if (encryption is EncryptionMetadata) {
        (encryption as EncryptionMetadata).metadataFile = metadataFile;
      }
      final content = await file.readAsBytes();
      final clearContent = await encryption.decrypt(content);
      return clearContent.bytes;
    }
    throw StateError('$path doesn\'t exist');
  }

  Future<void> writeAsString(
    String content,
    Encryption encryption, {
    Encoding encoding: utf8,
    bool flush: false,
  }) async {
    if (encryption is EncryptionMetadata) {
      (encryption as EncryptionMetadata).metadataFile = metadataFile;
    }
    final file = File(path);
    final contentBytes = encoding.encode(content);
    final digest = await encryption.encrypt(contentBytes);
    return file.writeAsBytes(digest.bytes, flush: flush, mode: FileMode.writeOnly);
  }

  Future<void> writeAsBytes(
    List<int> content,
    Encryption encryption, {
    bool flush: false,
  }) async {
    if (encryption is EncryptionMetadata) {
      (encryption as EncryptionMetadata).metadataFile = metadataFile;
    }
    final file = File(path);
    final digest = await encryption.encrypt(content);
    return file.writeAsBytes(digest.bytes, flush: flush, mode: FileMode.writeOnly);
  }
}
