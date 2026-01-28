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
users.MapPost("/login", UserLogin);
users.MapPost("/login-jwt", JTWUserLogin);
users.MapGet("/account-jwt", (ClaimsPrincipal user) =>
{
    var userId = user.FindFirstValue(ClaimTypes.NameIdentifier);
    var username = user.FindFirstValue(ClaimTypes.Name);

    return Results.Ok(new { userId, username });
})
.RequireAuthorization();

RouteGroupBuilder jwtSess = app.MapGroup("jwt_sess");


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


static async Task<IResult> UserLogin(UserCreateDTO userDTO, UserContext db)
{
    if (string.IsNullOrWhiteSpace(userDTO.Name)) return Results.BadRequest("Username required");
    if (string.IsNullOrWhiteSpace(userDTO.Password)) return Results.BadRequest("Password required");

    
    var user = await db.Users.SingleOrDefaultAsync(u => u.Name == userDTO.Name);
    if(user is null) return Results.Unauthorized();

    var hasher = new PasswordHasher<User>();

    if (string.IsNullOrWhiteSpace(user.Password)) return Results.Unauthorized();
    var result = hasher.VerifyHashedPassword(user, user.Password, userDTO.Password);
    if (result == PasswordVerificationResult.Failed) return Results.Unauthorized();
    if(result == PasswordVerificationResult.SuccessRehashNeeded)
    {
        user.Password = hasher.HashPassword(user, userDTO.Password);
        await db.SaveChangesAsync();
    }
    return Results.Ok($"You have successfully authenticated as {userDTO.Name}");    
}


static async Task<IResult> JTWUserLogin(
    UserCreateDTO userDTO,
    UserContext db,
    IConfiguration configuration)
{
    if (string.IsNullOrWhiteSpace(userDTO.Name))
        return Results.BadRequest("Username required");

    if (string.IsNullOrWhiteSpace(userDTO.Password))
        return Results.BadRequest("Password required");
    var user = await db.Users
        .AsTracking()
        .SingleOrDefaultAsync(u => u.Name == userDTO.Name);

    if (user is null)
        return Results.Unauthorized();

    var hasher = new PasswordHasher<User>();
    var result = hasher.VerifyHashedPassword(
        user,
        user.Password!,
        userDTO.Password
    );

    if (result == PasswordVerificationResult.Failed)
        return Results.Unauthorized();

    if (result == PasswordVerificationResult.SuccessRehashNeeded)
    {
        user.Password = hasher.HashPassword(user, userDTO.Password);
        await db.SaveChangesAsync();
    }

    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
        new Claim(JwtRegisteredClaimNames.UniqueName, user.Name!),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

    var key = new SymmetricSecurityKey(
        System.Text.Encoding.UTF8.GetBytes(configuration["JwtConfig:Key"]!)
    );

    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: configuration["JwtConfig:Issuer"],
        audience: configuration["JwtConfig:Audience"],
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(30),
        signingCredentials: creds
    );

    return Results.Ok(new
    {
        token = new JwtSecurityTokenHandler().WriteToken(token),
        expires = token.ValidTo
    });
}
