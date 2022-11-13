using CryptoUtils.Constants;

namespace CryptoUtils.Security.Cryptography
{
	public enum KeySizes
	{
		KeySize128Bits = 128,
		KeySize192Bits = 192,
		KeySize256Bits = 256
	}

	public static class KeySizesExtensions
	{
		public static int ToBytesSize(this KeySizes keySize)
			=> (int)keySize / ConstantValues.BitsPerByte;
	}
}
