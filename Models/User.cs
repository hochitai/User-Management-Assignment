namespace UserManagementAPI.Models
{
    public class User
    {
        public int Id { get; set; }

        public string Username { get; set; }

        public string Password { get; set; }

        public string Name { get; set; }

        public string Salt { get; set; }

        public string Permission { get; set; }

        public bool IsActive { get; set; }
    }
}
