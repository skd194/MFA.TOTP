namespace MFA.TOTP.Repository
{
    public class UserReporsitory : IUserRepository
    {
        private readonly Dictionary<string, AppUser> _users = new();
        public AppUser GetByEmail(string email) => _users.Values.FirstOrDefault(u => u.Email == email);
        public AppUser GetById(string id) => _users.TryGetValue(id, out var u) ? u : null;
        public void Update(AppUser user) => _users[user.Id] = user;
        public void Add(AppUser user) => _users[user.Id] = user;
    }
}
