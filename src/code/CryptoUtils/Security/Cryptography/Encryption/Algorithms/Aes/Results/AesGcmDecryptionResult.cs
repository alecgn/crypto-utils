namespace CryptoUtils.Security.Cryptography.Encryption.Algorithms.Aes
{
	public record AesGcmDecryptionResult : AesGcmBaseResult
	{
		public byte[] DecryptedData { get; set; }

		public string DecryptedText { get; set; }
	}
}
