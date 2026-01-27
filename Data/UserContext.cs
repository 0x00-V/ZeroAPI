using Microsoft.EntityFrameworkCore;
using ZeroAPI.Models;

class UserContext : DbContext
{
    public UserContext(DbContextOptions<UserContext> options) : base(options){}
    public DbSet<User> Users => Set<User>();
}