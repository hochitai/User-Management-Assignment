namespace UserManagementAPI.Models
{
    public class UserPasswordRequest
    {
        public int Id { get; set; }

        public string OldPassword { get; set; }

        public string NewPassword { get; set; }

    }
}
