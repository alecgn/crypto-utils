using CryptoUtils.Text.Encoding;

namespace CryptoUtils.Security.Cryptography.Encryption.Algorithms.Aes.Interfaces
{
    public interface IAesGcmBase : IEncryptionOperations
    {
        int TagSize { get; }
        int NonceSize { get; }
        int EncryptedDataMinimumSize { get; }
        IEncoder Encoder { get; }

        AesGcmEncryptionResult EncryptDataAndGetMetadata(byte[] dataToEncrypt);

        AesGcmEncryptionResult EncryptTextAndGetMetadata(string textToEncrypt);

        AesGcmDecryptionResult DecryptEncodedStringAndGetMetadata(string encodedEncryptedStringWithMetadata);

        AesGcmDecryptionResult DecryptDataAndGetMetadata(byte[] dataToDecryptWithMetadata);
    }
}
