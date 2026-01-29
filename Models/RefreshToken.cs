namespace ZeroAPI.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public User User { get; set; } = null!;
        public string TokenHash { get; set; } = null!;
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresUtc { get; set; }
        public DateTime? RevokedUtc { get; set; }
        public int? ReplacedByTokenId { get; set; }
        public RefreshToken? ReplacedByToken { get; set; }
        public bool IsActive => RevokedUtc is null && DateTime.UtcNow < ExpiresUtc;
    }
}

