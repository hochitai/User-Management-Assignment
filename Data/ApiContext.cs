using Microsoft.EntityFrameworkCore;
using UserManagementAPI.Models;

namespace UserManagementAPI.Data
{
    public class ApiContext : DbContext
    {
        public DbSet<User> Users  { get; set; }
        public ApiContext(DbContextOptions<ApiContext> options) : base(options) { 
 
        }

    

    }
}
