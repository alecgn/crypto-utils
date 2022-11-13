using CryptoUtils.Constants;
using System;
using System.Text.RegularExpressions;

namespace CryptoUtils.Text.Encoding
{
	public class Base64Encoder : IBase64Encoder
	{
		public int ChunkSize => 4;

		private static Regex _regexBase64String = null;

		public string Encode(string @string)
		{
			ValidateInputString(@string, nameof(@string));

			var stringBytes = @string.ToUTF8Bytes();

			return Encode(stringBytes);
		}

		public string Encode(byte[] bytes)
		{
			ValidateInputBytes(bytes);

			return bytes.ToBase64String();
		}

		public string DecodeToString(string base64String)
		{
			ValidateEncodedString(base64String);

			var bytes = DecodeToBytes(base64String);

			return bytes.ToUTF8String();
		}

		public byte[] DecodeToBytes(string base64String)
		{
			ValidateEncodedString(base64String);

			return base64String.FromBase64StringToBytes();
		}

		public void ValidateEncodedString(string base64String)
		{
			_regexBase64String ??= new Regex(RegexPatterns.Base64String, RegexOptions.Compiled);

			if (!(!string.IsNullOrWhiteSpace(base64String) &&
				_regexBase64String.IsMatch(base64String) &&
				base64String.Length % ChunkSize == 0)
			)
			{
				throw new ArgumentException("Invalid Base64 input string", nameof(base64String));
			}
		}

		public bool IsValidEncodedString(string base64String)
		{
			bool isValid = false;

			try
			{
				ValidateEncodedString(base64String);
				isValid = true;
			}
			catch { }

			return isValid;
		}

		private static void ValidateInputString(string @string, string paramName)
		{
			if (string.IsNullOrWhiteSpace(@string))
			{
				throw new ArgumentException("Input string required", paramName);
			}
		}

		private static void ValidateInputBytes(byte[] bytes)
		{
			if (bytes is null || bytes.Length is 0)
			{
				throw new ArgumentException("Invalid input bytes", nameof(bytes));
			}
		}
	}
}
