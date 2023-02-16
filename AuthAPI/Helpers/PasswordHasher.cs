using System.Security.Cryptography;

namespace AuthAPI.Helpers
{
    public class PasswordHasher
    {
        private static RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        private static readonly int SaltSize = 16;
        private static readonly int HashSize = 20;
        private static readonly int Interations = 10000;

        public static string HashPassword(string password)
        {
            byte[] salt;
            rng.GetBytes(salt = new byte[SaltSize]);
            var key = new Rfc2898DeriveBytes(password, salt, Interations);
            var hash = key.GetBytes(HashSize);
            var hashByte = new byte[SaltSize + HashSize];
            Array.Copy(salt, 0, hashByte, 0, SaltSize);
            Array.Copy(hash, 0, hashByte, SaltSize, HashSize);

            var base64hash = Convert.ToBase64String(hashByte);
            return base64hash;
        }

        public static bool VerifyPassword(string password, string base64Hash)
        {
            var hashBytes = Convert.FromBase64String(base64Hash);

            var salt = new byte[SaltSize];
            Array.Copy(hashBytes, 0, salt, 0, SaltSize);

            var key = new Rfc2898DeriveBytes(password, salt, Interations);
            byte[] hash = key.GetBytes(HashSize);
            for (int i = 0; i < hash.Length; i++)
            {
                if (hashBytes[i + SaltSize] != hash[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
