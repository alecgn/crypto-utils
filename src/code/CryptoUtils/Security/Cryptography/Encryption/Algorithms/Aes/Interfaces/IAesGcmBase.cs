namespace CryptoUtils.Security.Cryptography.Encryption.Algorithms.Aes
{
    public interface IAesGcmBase : IEncryptionOperations
    {
        AesGcmEncryptionResult EncryptDataAndGetMetadata(byte[] dataToEncrypt);

        AesGcmEncryptionResult EncryptTextAndGetMetadata(string textToEncrypt);

        AesGcmDecryptionResult DecryptEncodedStringAndGetMetadata(string encodedEncryptedStringWithMetadata);

        AesGcmDecryptionResult DecryptDataAndGetMetadata(byte[] dataToDecryptWithMetadata);
    }
}
