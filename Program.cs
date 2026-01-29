using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using ZeroAPI.DTOs;
using ZeroAPI.Models;
using ZeroAPI.Data;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<UserContext>(opt => opt.UseSqlite("Data Source=users.db"));
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    
}).AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
{
    ValidIssuer = builder.Configuration["JwtConfig:Issuer"],
    ValidAudience = builder.Configuration["JwtConfig:Audience"],
    IssuerSigningKey = new SymmetricSecurityKey(
        System.Text.Encoding.UTF8.GetBytes(builder.Configuration["JwtConfig:Key"]!)
    ),
    ValidateIssuer = true,
    ValidateAudience = true,
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    NameClaimType = JwtRegisteredClaimNames.UniqueName
};
 
});
builder.Services.AddAuthorization();


var app = builder.Build();

app.MapGet("/", (HttpContext context) =>
{
    return $"Stuck? Try {context.Request.GetDisplayUrl()}docs";
});
app.MapGet("/docs", (IWebHostEnvironment env) =>
{
    string mimeType = "text/html";
    var path = Path.Combine(env.ContentRootPath, "Docs", "documentation.html");
    return Results.File(path, contentType: mimeType);
});


RouteGroupBuilder users = app.MapGroup("/users");
users.MapGet("/", GetAllUsers);
users.MapPost("/register", RegisterUser);
users.MapPost("/login", Login);
users.MapPost("/refresh", RefreshAccessToken);
users.MapPost("/logout", LogoutRefreshToken);

app.MapGet("/protected", (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        message = "You are authenticated",
        claims = user.Claims.Select(c => new { c.Type, c.Value })
    });
})
.RequireAuthorization();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<UserContext>();
    db.Database.EnsureCreated();
}

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.Run();


static async Task<IResult> GetAllUsers(UserContext db)
{
    return TypedResults.Ok(await db.Users.Select(x => new UserDTO(x)).ToArrayAsync());
}


static async Task<IResult> RegisterUser(UserCreateDTO userDTO, UserContext db)
{
    if (string.IsNullOrWhiteSpace(userDTO.Name)) return Results.BadRequest("Username required");
    if (string.IsNullOrWhiteSpace(userDTO.Password)) return Results.BadRequest("Password required");

    var hasher = new PasswordHasher<User>();
    var user = new User{ Name = userDTO.Name};
    user.Password = hasher.HashPassword(user, userDTO.Password);

    var userAccount = new User
    {
        Name = userDTO.Name,
        Password = user.Password
    };
    try
    {
        db.Users.Add(userAccount);
        await db.SaveChangesAsync();
    }
    catch (DbUpdateException)
    {
        return Results.Conflict("User already exists");
    }
    
    userDTO = new UserCreateDTO(userAccount);
    return Results.Created(
    $"/users/{userAccount.Id}",
    new UserDTO(userAccount)
);
}

static string GenerateRefreshToken()
{
    var bytes = RandomNumberGenerator.GetBytes(32);
    return Convert.ToBase64String(bytes);
}

static string Sha256(string input)
{
    var bytes = System.Text.Encoding.UTF8.GetBytes(input);
    var hash = SHA256.HashData(bytes);
    return Convert.ToBase64String(hash);
}


static string CreateAccessToken(User user, IConfiguration config, DateTime utcNow, int minutes = 30)
{
    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
        new Claim(JwtRegisteredClaimNames.UniqueName, user.Name!),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };
    var key = new SymmetricSecurityKey(
        System.Text.Encoding.UTF8.GetBytes(config["JwtConfig:Key"]!)
    );
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: config["JwtConfig:Issuer"],
        audience: config["JwtConfig:Audience"],
        claims: claims,
        expires: utcNow.AddMinutes(minutes),
        signingCredentials: creds
    );
    return new JwtSecurityTokenHandler().WriteToken(token);
}

static async Task<IResult> Login(
    UserCreateDTO userDTO,
    UserContext db,
    IConfiguration configuration)
{
    if (string.IsNullOrWhiteSpace(userDTO.Name)) return Results.BadRequest("Username required");
    if (string.IsNullOrWhiteSpace(userDTO.Password)) return Results.BadRequest("Password required");

    var user = await db.Users.SingleOrDefaultAsync(u => u.Name == userDTO.Name);
    if (user is null) return Results.Unauthorized();

    var hasher = new PasswordHasher<User>();
    var result = hasher.VerifyHashedPassword(user, user.Password!, userDTO.Password);
    if (result == PasswordVerificationResult.Failed) return Results.Unauthorized();

    if (result == PasswordVerificationResult.SuccessRehashNeeded)
    {
        user.Password = hasher.HashPassword(user, userDTO.Password);
        await db.SaveChangesAsync();
    }

    var now = DateTime.UtcNow;
    var accessToken = CreateAccessToken(user, configuration, now, minutes: 30);
    var refreshToken = GenerateRefreshToken();
    var refreshTokenHash = Sha256(refreshToken);
    var refreshEntity = new RefreshToken
    {
        UserId = user.Id,
        TokenHash = refreshTokenHash,
        CreatedUtc = now,
        ExpiresUtc = now.AddDays(14)
    };

    db.RefreshTokens.Add(refreshEntity);
    await db.SaveChangesAsync();

    return Results.Ok(new
    {
        accessToken,
        accessExpires = now.AddMinutes(30),
        refreshToken = refreshToken,
        refreshExpires = refreshEntity.ExpiresUtc
    });
}

static async Task<IResult> RefreshAccessToken(
    RefreshRequestDTO dto,
    UserContext db,
    IConfiguration configuration)
{
    if (string.IsNullOrWhiteSpace(dto.RefreshToken))
        return Results.BadRequest("RefreshToken required");

    var now = DateTime.UtcNow;
    var incomingHash = Sha256(dto.RefreshToken);
    var stored = await db.RefreshTokens
        .Include(rt => rt.User)
        .SingleOrDefaultAsync(rt => rt.TokenHash == incomingHash);

    if (stored is null || !stored.IsActive)
        return Results.Unauthorized();

    var user = stored.User;
    stored.RevokedUtc = now;

    var newPlain = GenerateRefreshToken();
    var newHash = Sha256(newPlain);
    var replacement = new RefreshToken
    {
        UserId = user.Id,
        TokenHash = newHash,
        CreatedUtc = now,
        ExpiresUtc = now.AddDays(14)
    };
    db.RefreshTokens.Add(replacement);
    await db.SaveChangesAsync();
    var accessToken = CreateAccessToken(user, configuration, now, minutes: 30);
    return Results.Ok(new
    {
        accessToken,
        accessExpires = now.AddMinutes(30),
        refreshToken = newPlain,
        refreshExpires = replacement.ExpiresUtc
    });
}

static async Task<IResult> LogoutRefreshToken(
    RefreshRequestDTO dto,
    UserContext db)
{
    if (string.IsNullOrWhiteSpace(dto.RefreshToken))
        return Results.BadRequest("RefreshToken required");

    var hash = Sha256(dto.RefreshToken);

    var stored = await db.RefreshTokens.SingleOrDefaultAsync(rt => rt.TokenHash == hash);
    if (stored is null) return Results.Ok();

    stored.RevokedUtc = DateTime.UtcNow;
    await db.SaveChangesAsync();

    return Results.Ok("Logged out");
}
