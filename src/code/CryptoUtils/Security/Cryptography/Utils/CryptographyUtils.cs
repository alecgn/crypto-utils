using System.Security.Cryptography;

namespace CryptoUtils.Security.Cryptography
{
	public static class CryptographyUtils
	{
		public static byte[] GenerateRandomBytes(int length)
		{
			var randomBytes = new byte[length];
			RandomNumberGenerator.Fill(randomBytes);

			return randomBytes;
		}

		public static byte[] Generate128BitKey()
			=> GenerateRandomBytes(KeySizes.KeySize128Bits.ToBytesSize());

		public static byte[] Generate192BitKey()
			=> GenerateRandomBytes(KeySizes.KeySize192Bits.ToBytesSize());

		public static byte[] Generate256BitKey()
			=> GenerateRandomBytes(KeySizes.KeySize256Bits.ToBytesSize());

        public static void ValidateKey(byte[] key, KeySizes expectedKeySize)
        {
            if (key is null || key.Length != expectedKeySize.ToBytesSize())
            {
                throw new ArgumentException("Invalid key.", nameof(key));
            }
        }
    }
}
