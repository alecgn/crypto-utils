namespace CryptoUtils.Security.Cryptography.Encryption
{
	public interface IEncryptionOperations
	{
		#region Encryption

		string EncryptTextToEncodedString(string textToEncrypt);

		byte[] EncryptTextToBytes(string textToEncrypt);

		string EncryptDataToEncodedString(byte[] dataToEncrypt);

		byte[] EncryptDataToBytes(byte[] dataToEncrypt);

		#endregion Encryption


		#region Decryption

		string DecryptEncodedStringToText(string encodedEncryptedStringWithMetadata);

		string DecryptDataToText(byte[] dataToDecryptWithMetadata);

		byte[] DecryptEncodedStringToBytes(string encodedEncryptedStringWithMetadata);

		byte[] DecryptDataToBytes(byte[] dataToDecryptWithMetadata);

		#endregion Decryption
	}
}
