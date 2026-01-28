using Microsoft.EntityFrameworkCore;
using ZeroAPI.Models;

namespace ZeroAPI.Data
{
    public class UserContext : DbContext
{
    public UserContext(DbContextOptions<UserContext> options) : base(options){}
    public DbSet<User> Users => Set<User>();
}
}
