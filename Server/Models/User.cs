using System.ComponentModel.DataAnnotations;

namespace Server.Models
{
    public class User
    {
        public Guid Id { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public string RefreshTokenExpiryTime { get; set; }

        public User(string userName, string password, string refreshToken, string refreshTokenExpiryTime)
        {
            Id = Guid.NewGuid();
            UserName = userName;
            Password = password;
            RefreshToken = refreshToken;
            RefreshTokenExpiryTime = refreshTokenExpiryTime;
        }
    }
}
