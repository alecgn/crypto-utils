using CryptoUtils.Security.Cryptography.Encryption.Algorithms.Aes.Interfaces;
using CryptoUtils.Text;
using CryptoUtils.Text.Encoding;
using System.Security.Cryptography;

namespace CryptoUtils.Security.Cryptography.Encryption.Algorithms.Aes
{
    public abstract class AesGcmBase : IAesGcmBase
	{
		#region Fields

		private readonly byte[] _key;
		private readonly AesGcm _aesGcm;
		private readonly IEncoder _encoder;

		#endregion Fields


		#region Properties

		public int TagSize => AesGcm.TagByteSizes.MaxSize;
		public int NonceSize => AesGcm.NonceByteSizes.MaxSize;
		public int EncryptedDataMinimumSize => 1;
		public IEncoder Encoder => _encoder;

		#endregion Properties


		#region Constructors/Destructors

		public AesGcmBase(byte[] key, IEncoder encoder)
		{
			_key = key;
			_aesGcm = new(_key);
			_encoder = encoder;
		}

		~AesGcmBase()
		{
			_aesGcm?.Dispose();
		}

		#endregion Constructors/Destructors


		#region Encryption

		/// <summary>
		/// Encrypts an input plain text and returns an encoded string with the concatenation of the encrypted text + generated metadata (tag + nonce).
		/// </summary>
		/// <param name="textToEncrypt">The plain text to be encrypted.</param>
		/// <returns>The encoded string with the concatenation of the encrypted text + generated metadata (tag + nonce).</returns>
		/// <exception cref="ArgumentException"></exception>
		public string EncryptTextToEncodedString(string textToEncrypt)
		{
			var textToEncryptBytes = textToEncrypt.ToUTF8Bytes();
			var encryptedTextBytesWithMetadata = EncryptDataToBytes(textToEncryptBytes);

			return _encoder.Encode(encryptedTextBytesWithMetadata);
		}

		/// <summary>
		/// Encrypts an input plain text and returns a byte array with the concatenation of the encrypted text + generated metadata (tag + nonce).
		/// </summary>
		/// <param name="textToEncrypt">The plain text to be encrypted.</param>
		/// <returns>The byte array with the concatenation of the encrypted text + generated metadata (tag + nonce).</returns>
		/// <exception cref="ArgumentException"></exception>
		public byte[] EncryptTextToBytes(string textToEncrypt)
		{
			var textToEncryptBytes = textToEncrypt.ToUTF8Bytes();
			var encryptedTextBytesWithMetadata = EncryptDataToBytes(textToEncryptBytes);

			return encryptedTextBytesWithMetadata;
		}

		/// <summary>
		/// Encrypts an input data and returns an encoded string with the concatenation of the encrypted data + generated metadata (tag + nonce).
		/// </summary>
		/// <param name="dataToEncrypt">The data to be encrypted.</param>
		/// <returns>The encoded string with the concatenation of the encrypted data + generated metadata (tag + nonce).</returns>
		/// <exception cref="ArgumentException"></exception>
		public string EncryptDataToEncodedString(byte[] dataToEncrypt)
		{
			var encryptedDataWithMetadata = EncryptDataToBytes(dataToEncrypt);
			var encodedEncryptedDataWithMetadata = _encoder.Encode(encryptedDataWithMetadata);

			return encodedEncryptedDataWithMetadata;
		}

		/// <summary>
		/// Encrypts an input data and returns a byte array with the concatenation of the encrypted data + generated metadata (tag + nonce).
		/// </summary>
		/// <param name="dataToEncrypt">The data to be encrypted.</param>
		/// <returns>The byte array with the concatenation of the encrypted data + generated metadata (tag + nonce).</returns>
		/// <exception cref="ArgumentException"></exception>
		public byte[] EncryptDataToBytes(byte[] dataToEncrypt)
		{
			ValidateInputData(dataToEncrypt, nameof(dataToEncrypt));

			var nonce = GenerateNonce();
			var tag = new byte[TagSize];
			var encryptedData = new byte[dataToEncrypt.Length];

			EncryptDataInternal(dataToEncrypt, tag, nonce, encryptedData);

			var encryptedDataWithMetadata = GetEncryptedDataWithMetadata(encryptedData, tag, nonce);

			return encryptedDataWithMetadata;
		}

		/// <summary>
		/// Encrypts an input plain text and returns an object with the encrypted text and the generated metadata (key, tag, nonce, etc.).
		/// </summary>
		/// <param name="textToEncrypt">The text to be encrypted.</param>
		/// <returns>An object with the encrypted text and the generated metadata (key, tag, nonce, etc.).</returns>
		/// <exception cref="ArgumentException"></exception>
		public AesGcmEncryptionResult EncryptTextAndGetMetadata(string textToEncrypt)
		{
			var textToEncryptBytes = textToEncrypt.ToUTF8Bytes();
			var encryptionResult = EncryptDataAndGetMetadata(textToEncryptBytes);

			return encryptionResult;
		}

		/// <summary>
		/// Encrypts an input data and returns an object with the encrypted data and the generated metadata (key, tag, nonce, etc.).
		/// </summary>
		/// <param name="dataToEncrypt">The data to be encrypted.</param>
		/// <returns>An object with the encrypted data and the generated metadata (key, tag, nonce, etc.).</returns>
		/// <exception cref="ArgumentException"></exception>
		public AesGcmEncryptionResult EncryptDataAndGetMetadata(byte[] dataToEncrypt)
		{
			ValidateInputData(dataToEncrypt, nameof(dataToEncrypt));

			var nonce = GenerateNonce();
			var tag = new byte[TagSize];
			var encryptedData = new byte[dataToEncrypt.Length];

			EncryptDataInternal(dataToEncrypt, tag, nonce, encryptedData);

			var encryptedDataWithMetadata = GetEncryptedDataWithMetadata(encryptedData, tag, nonce);

			return new()
			{
				Key = _key,
				Nonce = nonce,
				Tag = tag,
				EncryptedData = encryptedData,
				EncryptedDataWithMetadata = encryptedDataWithMetadata,
				EncodedEncryptedDataWithMetadata = _encoder.Encode(encryptedDataWithMetadata)
			};
		}

		#endregion Encryption


		#region Decryption

		/// <summary>
		/// Decrypts an input encoded encrypted string with metadata appended (tag + nonce) to plaint text.
		/// </summary>
		/// <param name="encodedEncryptedStringWithMetadata">The encoded encrypted string with metadata appended (tag + nonce) to be decrypted.</param>
		/// <returns>The decrypted plain text.</returns>
		/// <exception cref="ArgumentException"></exception>
		public string DecryptEncodedStringToText(string encodedEncryptedStringWithMetadata)
		{
			var decodedEncryptedDataWithMetadata = _encoder.DecodeToBytes(encodedEncryptedStringWithMetadata);
			var decryptedData = DecryptDataToBytes(decodedEncryptedDataWithMetadata);
			var decryptedText = decryptedData.ToUTF8String();

			return decryptedText;
		}

		/// <summary>
		/// Decrypts an input encrypted data with metadata appended (tag + nonce) to plaint text.
		/// </summary>
		/// <param name="dataToDecryptWithMetadata">The encrypted data with metadata appended (tag + nonce) to be decrypted.</param>
		/// <returns>The decrypted plain text.</returns>
		/// <exception cref="ArgumentException"></exception>
		public string DecryptDataToText(byte[] dataToDecryptWithMetadata)
		{
			var decryptedData = DecryptDataToBytes(dataToDecryptWithMetadata);
			var decryptedText = decryptedData.ToUTF8String();

			return decryptedText;
		}

		/// <summary>
		/// Decrypts an input encoded encrypted string with metadata appended (tag + nonce) to a byte array.
		/// </summary>
		/// <param name="encodedEncryptedStringWithMetadata">The encoded encrypted string with metadata appended (tag + nonce) to be decrypted.</param>
		/// <returns>The decrypted byte array.</returns>
		/// <exception cref="ArgumentException"></exception>
		public byte[] DecryptEncodedStringToBytes(string encodedEncryptedStringWithMetadata)
		{
			var dataToDecryptWithMetadata = _encoder.DecodeToBytes(encodedEncryptedStringWithMetadata);

			return DecryptDataToBytes(dataToDecryptWithMetadata);
		}

		/// <summary>
		/// Decrypts an input encrypted data with metadata appended (tag + nonce) to a byte array.
		/// </summary>
		/// <param name="dataToDecryptWithMetadata">The encrypted data with metadata appended (tag + nonce) to be decrypted.</param>
		/// <returns>The decrypted byte array.</returns>
		/// <exception cref="ArgumentException"></exception>
		public byte[] DecryptDataToBytes(byte[] dataToDecryptWithMetadata)
		{
			ValidateInputData(dataToDecryptWithMetadata, nameof(dataToDecryptWithMetadata));

			var (encryptedData, tag, nonce) = GetMetadataFromEncryptedData(dataToDecryptWithMetadata);
			var decryptedData = new byte[encryptedData.Length];

			DecryptDataInternal(encryptedData, tag, nonce, decryptedData);

			return decryptedData;
		}

		/// <summary>
		/// Decrypts an input encoded encrypted string with metadata appended (tag + nonce).
		/// </summary>
		/// <param name="encodedEncryptedStringWithMetadata">The encoded encrypted string with metadata appended (tag + nonce).</param>
		/// <returns>An object with the decrypted data and the generated metadata (key, tag, nonce, etc.)</returns>
		/// <exception cref="ArgumentException"></exception>
		public AesGcmDecryptionResult DecryptEncodedStringAndGetMetadata(string encodedEncryptedStringWithMetadata)
		{
			var decodedEncryptedDataWithMetadata = _encoder.DecodeToBytes(encodedEncryptedStringWithMetadata);
			var decryptionResult = DecryptDataAndGetMetadata(decodedEncryptedDataWithMetadata);

			return decryptionResult;
		}

		/// <summary>
		/// Decrypts an input encrypted data with metadata appended (tag + nonce).
		/// </summary>
		/// <param name="dataToDecryptWithMetadata">The encrypted byte array with metadata appended (tag + nonce).</param>
		/// <returns>An object with the decrypted data and the generated metadata (key, tag, nonce, etc.)</returns>
		/// <exception cref="ArgumentException"></exception>
		public AesGcmDecryptionResult DecryptDataAndGetMetadata(byte[] dataToDecryptWithMetadata)
		{
			ValidateInputData(dataToDecryptWithMetadata, nameof(dataToDecryptWithMetadata));

			var (encryptedBytes, tag, nonce) = GetMetadataFromEncryptedData(dataToDecryptWithMetadata);
			var decryptedBytes = new byte[encryptedBytes.Length];

			DecryptDataInternal(encryptedBytes, tag, nonce, decryptedBytes);

			return new()
			{
				Key = _key,
				Nonce = nonce,
				Tag = tag,
				DecryptedData = decryptedBytes,
				DecryptedText = TryGetDecryptedText(decryptedBytes)
			};
		}

		#endregion Decryption


		#region Private Methods

		private static void ValidateInputData(byte[] inputData, string paramName)
		{
			if (inputData is null || inputData.Length is 0)
			{
				throw new ArgumentException($@"""{nameof(inputData)}"" cannot be null or empty.", paramName);
			}
		}

		private byte[] GenerateNonce()
			=> CryptographyUtils.GenerateRandomBytes(NonceSize);

		private void EncryptDataInternal(byte[] dataToEncrypt, byte[] tag, byte[] nonce, byte[] encryptedData)
			=> _aesGcm.Encrypt(
				nonce,
				dataToEncrypt,
				encryptedData,
				tag
			);

		private byte[] GetEncryptedDataWithMetadata(
			byte[] encryptedData,
			byte[] tag,
			byte[] nonce
		)
		{
			var encryptedDataWithMetadataSize = GetEncryptedDataWithMetadataSize(encryptedData.Length);
			var encryptedDataWithMetada = new byte[encryptedDataWithMetadataSize];

			Array.Copy(
				encryptedData,
				0,
				encryptedDataWithMetada,
				0,
				encryptedData.Length
			);

			Array.Copy(
				tag,
				0,
				encryptedDataWithMetada,
				encryptedData.Length,
				TagSize
			);

			Array.Copy(
				nonce,
				0,
				encryptedDataWithMetada,
				encryptedData.Length + TagSize,
				NonceSize
			);

			return encryptedDataWithMetada;
		}

		private int GetEncryptedDataWithMetadataSize(int encryptedDataSize)
			=> encryptedDataSize + TagSize + NonceSize;

		private (byte[] EncryptedData, byte[] Tag, byte[] Nonce) GetMetadataFromEncryptedData(byte[] encrypteDataWithMetada)
		{
			ValidateEncryptedDataWithMetadataSize(encrypteDataWithMetada);

			var encryptedData = new byte[encrypteDataWithMetada.Length - NonceSize - TagSize];

			Array.Copy(
				encrypteDataWithMetada,
				0,
				encryptedData,
				0,
				encryptedData.Length
			);

			var tag = new byte[TagSize];

			Array.Copy(
				encrypteDataWithMetada,
				encryptedData.Length,
				tag,
				0,
				TagSize
			);

			var nonce = new byte[NonceSize];

			Array.Copy(
				encrypteDataWithMetada,
				encryptedData.Length + TagSize,
				nonce,
				0,
				NonceSize
			);

			return (EncryptedData: encryptedData, Tag: tag, Nonce: nonce);
		}

		private void DecryptDataInternal(byte[] encryptedDataToDecrypt, byte[] tag, byte[] nonce, byte[] decryptedData)
			=> _aesGcm.Decrypt(
				nonce,
				encryptedDataToDecrypt,
				tag,
				decryptedData
			);

		private void ValidateEncryptedDataWithMetadataSize(byte[] encryptedDataWithMetada)
		{
			if (encryptedDataWithMetada is null ||
				encryptedDataWithMetada.Length < NonceSize + TagSize + EncryptedDataMinimumSize
			)
			{
				throw new ArgumentException("Data to decrypt is not valid (wrong size/length).", nameof(encryptedDataWithMetada));
			}
		}

		private static string TryGetDecryptedText(byte[] decryptedBytes)
		{
			var decryptedText = string.Empty;

			try
			{
				decryptedText = decryptedBytes.ToUTF8String();
			}
			// not all decrypted data is an UTF8 text, leave empty if it's not
			catch { }

			return decryptedText;
		}

		#endregion Private Methods
	}
}
