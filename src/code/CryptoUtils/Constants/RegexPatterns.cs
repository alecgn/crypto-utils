namespace CryptoUtils.Constants
{
	internal static class RegexPatterns
	{
		internal const string Base64String = @"^[a-zA-Z0-9+\/=]{4,}$";

		internal const string HexadecimalString = @"^(0(?:x|X))?([0-9a-fA-F]{2,})$";
	}
}
