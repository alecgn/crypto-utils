namespace CryptoUtils.Security.Cryptography.Encryption.Algorithms.Aes.Results
{
    public abstract class AesGcmBaseResult
    {
        public byte[] Key { get; set; }
        public byte[] Nonce { get; set; }
        public byte[] Tag { get; set; }
    }
}
