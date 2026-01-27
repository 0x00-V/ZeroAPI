using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ZeroAPI.DTOs;
using ZeroAPI.Models;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<UserContext>(opt => opt.UseSqlite("Data Source=users.db"));


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

app.UseStaticFiles();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<UserContext>();
    db.Database.EnsureCreated();
}


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
    return TypedResults.Created($"ID: {userAccount.Id}, Name: {userAccount.Name}");
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
