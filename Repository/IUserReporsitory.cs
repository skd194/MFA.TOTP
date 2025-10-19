namespace MFA.TOTP.Repository
{

    public interface IUserRepository
    {
        AppUser GetByEmail(string email);
        AppUser GetById(string id);
        void Update(AppUser user);
        void Add(AppUser user);
    }
}
