using Microsoft.EntityFrameworkCore;
using ZeroAPI.Models;

namespace ZeroAPI.Data
{
public class UserContext : DbContext
{
    public UserContext(DbContextOptions<UserContext> options) : base(options) {}

    public DbSet<User> Users => Set<User>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Name)
            .IsUnique();

        modelBuilder.Entity<RefreshToken>()
            .HasOne(rt => rt.User)
            .WithMany(u => u.RefreshTokens)
            .HasForeignKey(rt => rt.UserId);
    }
}

}
