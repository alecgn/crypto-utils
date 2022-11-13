namespace CryptoUtils.Security.Cryptography.Encryption.Algorithms.Aes
{
    public abstract record AesGcmBaseResult
    {
        public byte[] Key { get; set; }
        public byte[] Nonce { get; set; }
        public byte[] Tag { get; set; }
    }
}
