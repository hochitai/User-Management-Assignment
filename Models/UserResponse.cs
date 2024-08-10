namespace UserManagementAPI.Models
{
    public class UserResponse
    {
        public UserResponse(int id, string username, string name, string permission, string token)
        {
            Id = id;
            Username = username;
            Name = name;
            Permission = permission;
            Token = token;
        }

        public int Id { get; set; }

        public string Username { get; set; }

        public string Name { get; set; }

        public string Permission { get; set; }

        public string Token { get; set; }
    }
}
