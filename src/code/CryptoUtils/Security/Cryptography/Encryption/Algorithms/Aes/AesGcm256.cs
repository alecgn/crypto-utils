using CryptoUtils.Text.Encoding;

namespace CryptoUtils.Security.Cryptography.Encryption.Algorithms.Aes
{
	public class AesGcm256 : AesGcmBase, IAesGcm256
	{
		private const KeySizes _aesKeySize = KeySizes.KeySize256Bits;

		public AesGcm256(byte[] key, IEncoder encoder) : base(ValidateAESKey(key).Invoke(), encoder) { }

		// creates a random cryptographic key if a valid one is not provided.
		// this key can be retrieved after from metadata in the result object.
		public AesGcm256(IEncoder encoder)
			: base(CryptographyUtils.GenerateRandomBytes(_aesKeySize.ToBytesSize()), encoder) { }

		private static Func<byte[]> ValidateAESKey(byte[] key)
		{
			byte[] funcValidateAESKey()
			{
                CryptographyUtils.ValidateKey(key, _aesKeySize);

				return key;
			}

			return funcValidateAESKey;
		}
	}
}
