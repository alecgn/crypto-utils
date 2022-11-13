using CryptoUtils.Security.Cryptography.Encryption.Algorithms.Aes.Results;

namespace CryptoUtils.Security.Cryptography.Encryption.Algorithms.Aes
{
    public class AesGcmDecryptionResult : AesGcmBaseResult
	{
		public byte[] DecryptedData { get; set; }

		public string DecryptedText { get; set; }
	}
}
