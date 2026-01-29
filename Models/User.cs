using Microsoft.EntityFrameworkCore;


namespace ZeroAPI.Models
{
    [Index(nameof(Name), IsUnique = true)]
    public class User
{
    public int Id { get; set; }
    public string? Name { get; set; }
    public string? Password { get; set; }

    public List<RefreshToken> RefreshTokens { get; set; } = new();
}

} 