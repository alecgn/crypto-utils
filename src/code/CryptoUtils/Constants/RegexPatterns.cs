namespace CryptoUtils.Constants
{
    internal static class RegexPatterns
    {
        internal const string Base64String = @"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$";

        internal const string HexadecimalString = @"^(?:0(?:x|X))?([0-9a-fA-F]{2})+$";
    }
}
