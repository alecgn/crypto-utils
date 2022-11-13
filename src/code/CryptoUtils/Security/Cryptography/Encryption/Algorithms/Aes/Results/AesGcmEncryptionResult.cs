namespace CryptoUtils.Security.Cryptography.Encryption.Algorithms.Aes
{
	public record AesGcmEncryptionResult : AesGcmBaseResult
	{
		public byte[] EncryptedData { get; set; }

        /// <summary>
        /// Concatenation of Encrypted Data + Tag + Nonce
        /// </summary>
        public byte[] EncryptedDataWithMetadata { get; set; }

        /// <summary>
        /// Encoded concatenation of Encrypted Data + Tag + Nonce
        /// </summary>
        public string EncodedEncryptedDataWithMetadata { get; set; }
	}
}
