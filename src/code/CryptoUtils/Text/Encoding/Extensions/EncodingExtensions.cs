namespace CryptoUtils.Text.Encoding
{
	public static class EncodingExtensions
	{
		public static byte[] FromBase64StringToBytes(this string base64String) =>
			Convert.FromBase64String(base64String);

		public static string ToBase64String(this byte[] bytes) =>
			Convert.ToBase64String(bytes);
	}
}
