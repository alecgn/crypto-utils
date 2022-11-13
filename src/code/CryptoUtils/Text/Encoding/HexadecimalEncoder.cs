using CryptoUtils.Constants;
using System.Text;
using System.Text.RegularExpressions;

namespace CryptoUtils.Text.Encoding
{
	public class HexadecimalEncoder : IHexadecimalEncoder
	{
		public int ChunkSize => 2;

		private const int _hexadecimalBase = 16;
		private const string _hexadecimalPrefix = "0x";
		private const string _hexadecimalFormat = "x2";
		private static Regex _regexHexadecimalString = null;


		public string Encode(string @string)
		{
			ValidateInputString(@string, nameof(@string));

			var stringBytes = @string.ToUTF8Bytes();

			return Encode(stringBytes);
		}

		public string Encode(byte[] bytes)
		{
			ValidateInputBytes(bytes);

			var hexadecimalString = new StringBuilder();

			for (var i = 0; i < bytes.Length; i++)
			{
				hexadecimalString.Append(bytes[i].ToString(_hexadecimalFormat));
			}

			return hexadecimalString.ToString();
		}

		public string DecodeToString(string hexadecimalString)
		{
			ValidateEncodedString(hexadecimalString);
			SanitizeHexadecimalString(ref hexadecimalString);

			var bytes = DecodeToBytes(hexadecimalString);

			return bytes.ToUTF8String();
		}

		public byte[] DecodeToBytes(string hexadecimalString)
		{
			ValidateEncodedString(hexadecimalString);
			SanitizeHexadecimalString(ref hexadecimalString);

			var bytes = new byte[hexadecimalString.Length / ChunkSize];
			var i = 0;

			foreach (var hexadecimalValue in ChunkHexadecimalString(hexadecimalString))
			{
				bytes[i] = Convert.ToByte(hexadecimalValue, _hexadecimalBase);
				i++;
			}

			return bytes;
		}

		public void ValidateEncodedString(string hexadecimalString)
		{
			_regexHexadecimalString ??= new Regex(RegexPatterns.HexadecimalString, RegexOptions.Compiled);

			if (!(!string.IsNullOrWhiteSpace(hexadecimalString) &&
				_regexHexadecimalString.IsMatch(hexadecimalString) &&
				hexadecimalString.Length % ChunkSize == 0)
			)
			{
				throw new ArgumentException("Invalid Hexadecimal input string", nameof(hexadecimalString));
			}
		}

		public bool IsValidEncodedString(string hexadecimalString)
		{
			bool isValid = false;

			try
			{
				ValidateEncodedString(hexadecimalString);
				isValid = true;
			}
			catch { }

			return isValid;
		}

		private IEnumerable<string> ChunkHexadecimalString(string hexadecimalString)
		{
			for (var i = 0; i < hexadecimalString.Length; i += ChunkSize)
			{
				yield return hexadecimalString.Substring(i, ChunkSize);
			}
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
			if (bytes is null || bytes.Length == 0)
			{
				throw new ArgumentException("Invalid input bytes", nameof(bytes));
			}
		}

		private void SanitizeHexadecimalString(ref string hexadecimalString)
		{
			if (hexadecimalString.StartsWith(_hexadecimalPrefix, StringComparison.OrdinalIgnoreCase))
			{
				hexadecimalString = hexadecimalString[2..];
			}
		}
	}
}
