namespace MFA.TOTP.Repository
{
    public class AppUser
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; } // your chosen hashing scheme
        public bool TwoFactorEnabled { get; set; }
        public string ProtectedTotpSecret { get; set; } // encrypted via DataProtection
    }
}
