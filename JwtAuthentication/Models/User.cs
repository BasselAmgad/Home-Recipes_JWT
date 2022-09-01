using System.ComponentModel.DataAnnotations;

namespace Server.Models
{
    public class User
    {
        public Guid Id { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }

        public User(string userName, string password)
        {
            Id = Guid.NewGuid();
            UserName = userName;
            Password = password;
        }
    }
}
