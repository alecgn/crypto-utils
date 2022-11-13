using CryptoUtils.Security.Cryptography.Encryption.Algorithms.Aes.Results;

namespace CryptoUtils.Security.Cryptography.Encryption.Algorithms.Aes
{
    public class AesGcmEncryptionResult : AesGcmBaseResult
	{
		public byte[] EncryptedData { get; set; }

		/// <summary>
		/// Concatenation of Nonce + Tag + Encrypted Data
		/// </summary>
		public byte[] EncryptedDataWithMetadata { get; set; }

		/// <summary>
		/// Encoded concatenation of Nonce + Tag + Encrypted Data
		/// </summary>
		public string EncodedEncryptedDataWithMetadata { get; set; }
	}
}
