using System.ComponentModel.DataAnnotations;

namespace Server.Models
{
    public class User
    {
        public Guid Id { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public byte[] PasswordSalt { get; set; }
        public string RefreshToken { get; set; }
        public string RefreshTokenExpiryTime { get; set; }

        public User(string userName, string password, byte[] passwordSalt,string refreshToken, string refreshTokenExpiryTime)
        {
            Id = Guid.NewGuid();
            UserName = userName;
            Password = password;
            PasswordSalt = passwordSalt;
            RefreshToken = refreshToken;
            RefreshTokenExpiryTime = refreshTokenExpiryTime;
        }
    }
}
