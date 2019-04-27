import 'package:crypted_files/crypted_files.dart';

main() async {
  final passPhrase = 'MySuperSecurePassPhrase';
  final file = EncryptedFile('./example/test.txt', binaryFolder: './');

  await file.writeAsString('Test of the content', SecretBoxEncryption(passPhrase));

  print(await file.readAsString(SecretBoxEncryption(passPhrase)));
}