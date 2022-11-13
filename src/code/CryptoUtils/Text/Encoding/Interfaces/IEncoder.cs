namespace CryptoUtils.Text.Encoding
{
	public interface IEncoder
	{
		string Encode(string plainString);

		string Encode(byte[] byteArray);

		string DecodeToString(string encodedString);

		byte[] DecodeToBytes(string encodedString);

		void ValidateEncodedString(string encodedString);

		bool IsValidEncodedString(string encodedString);

		int ChunkSize { get; }
	}
}
