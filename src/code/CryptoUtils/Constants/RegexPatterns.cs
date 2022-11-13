namespace CryptoUtils.Constants
{
	public static class RegexPatterns
	{
		public const string Base64String = @"^[a-zA-Z0-9+\/=]{4,}$";

		public const string HexadecimalString = @"^(0(?:x|X))?([0-9a-fA-F]{2,})$";
	}
}
