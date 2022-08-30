
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Server.Models;
using Server.Utility;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

using IHost host = Host.CreateDefaultBuilder(args).Build();

builder.Services.AddControllers();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSingleton<Data>();
builder.Services.AddAntiforgery(options => options.HeaderName = "X-XSRF-TOKEN");

builder.Services.AddCors(options =>
{
    options.AddPolicy(name: "localhostOnly",
                      policy =>
                      {
                          policy.WithOrigins(builder.Configuration["clientUrl"])
                                .AllowAnyHeader()
                                .AllowAnyMethod()
                                .AllowCredentials();
                      });
});
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey
        (Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = false,
        ValidateIssuerSigningKey = true
    };
});

var app = builder.Build();


app.UseSwagger();
app.UseSwaggerUI();
app.UseAuthorization();
app.UseAuthentication();
app.UseHttpsRedirection();
app.UseCors("localhostOnly");

app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
    options.RoutePrefix = string.Empty;
});

app.MapPost("/security/register", async (Data data, [FromBody] User newUser) =>
{
    var hasher = new PasswordHasher<User>();
    var usersList = await data.GetUsersAsync();
    if (usersList is null)
        throw new Exception("Could not deserialize users list");
    if (usersList.Find(x => x.UserName == newUser.UserName) != null)
        return Results.BadRequest("username already exists");
    byte[] salt = RandomNumberGenerator.GetBytes(128 / 8);
    // derive a 256-bit subkey (use HMACSHA256 with 100,000 iterations)
    string hashedPassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
        password: newUser.Password!,
        salt: salt,
        prf: KeyDerivationPrf.HMACSHA256,
        iterationCount: 100000,
        numBytesRequested: 256 / 8));
    User newRegisteredUser = new User(newUser.UserName, hashedPassword, salt, string.Empty, string.Empty);
    await data.AddUserAsync(newRegisteredUser);
    return Results.Ok();
});

app.MapPost("/security/login", [AllowAnonymous] async (Data data, [FromBody] User userLogin) =>
{
    var hasher = new PasswordHasher<User>();
    TokenService _tokenService = new TokenService();
    var usersList = await data.GetUsersAsync();
    if (usersList is null)
        throw new Exception("Could not deserialize users list");
    var user = usersList.FirstOrDefault(u => u.UserName == userLogin.UserName);
    if (user is null)
        return Results.Unauthorized();
    var loginPasswordHash = hasher.VerifyHashedPassword(user, user.Password, userLogin.Password);
    if (loginPasswordHash.Equals(0))
        return Results.Unauthorized();
    var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName)
        };
    var accessToken = _tokenService.GenerateAccessToken(claims);
    var refreshToken = _tokenService.GenerateRefreshToken();
    user.RefreshToken = refreshToken;
    user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7).ToString();
    await data.SaveDataAsync();
    return Results.Ok(new AuthenticatedResponse { RefreshToken = refreshToken, Token = accessToken, UserName = user.UserName });
});

app.MapPost("/security/createToken",
[AllowAnonymous] (User user) =>
{
        var issuer = builder.Configuration["Jwt:Issuer"];
        var audience = builder.Configuration["Jwt:Audience"];
        var key = Encoding.ASCII.GetBytes
        (builder.Configuration["Jwt:Key"]);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("Id", Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Email, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,
                Guid.NewGuid().ToString())
             }),
            Expires = DateTime.UtcNow.AddMinutes(5),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = new SigningCredentials
            (new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha512Signature)
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = tokenHandler.WriteToken(token);
        var stringToken = tokenHandler.WriteToken(token);
        return Results.Ok(stringToken);
});

app.MapGet("/antiforgery", (IAntiforgery antiforgery, HttpContext context) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    context.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!, new CookieOptions { HttpOnly = false });
});

app.MapGet("/recipes", async (Data data, HttpContext context, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        var recipes = await data.GetRecipesAsync();
        return Results.Ok(recipes);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

app.MapGet("/recipes/{id}", async (Data data, IAntiforgery antiforgery, HttpContext context, Guid id) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        Recipe recipe = await data.GetRecipeAsync(id);
        return Results.Ok(recipe);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }

});

app.MapPost("/recipes", async (Data data, IAntiforgery antiforgery, HttpContext context, Recipe recipe) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        recipe.Id = Guid.NewGuid();
        await data.AddRecipeAsync(recipe);
        return Results.Created($"/recipes/{recipe.Id}", recipe);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }

});

app.MapPut("/recipes/{id}", async (Data data, IAntiforgery antiforgery, HttpContext context, Guid id, Recipe newRecipe) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        var updatedRecipe = await data.EditRecipeAsync(id, newRecipe);
        return Results.Ok(updatedRecipe);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }

});

app.MapDelete("/recipes/{id}", async (Data data, IAntiforgery antiforgery, HttpContext context, Guid id) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        await data.RemoveRecipeAsync(id);
        return Results.Ok();
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }

});

app.MapGet("/categories", async (Data data, IAntiforgery antiforgery, HttpContext context) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        var categories = await data.GetCategoriesAsync();
        return Results.Ok(categories);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
}).RequireAuthorization();

app.MapPost("/categories", async (Data data, IAntiforgery antiforgery, HttpContext context, string category) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        await data.AddCategoryAsync(category);
        return Results.Created($"/categories/{category}", category);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

app.MapPut("/categories", async (Data data, IAntiforgery antiforgery, HttpContext context, string category, string newCategory) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        await data.EditCategoryAsync(category, newCategory);
        return Results.Ok($"Category ({category}) updated to ({newCategory})");
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

app.MapDelete("/categories", async (Data data, IAntiforgery antiforgery, HttpContext context, string category) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        await data.RemoveCategoryAsync(category);
        return Results.Ok();
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

app.MapPost("/recipes/category", async (Data data, IAntiforgery antiforgery, HttpContext context, Guid id, string category) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        await data.AddCategoryToRecipeAsync(id, category);
        return Results.Created($"recipes/category/{category}", category);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

app.MapDelete("/recipes/category", async (Data data, IAntiforgery antiforgery, HttpContext context, Guid id, string category) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        await data.RemoveCategoryFromRecipeAsync(id, category);
        return Results.Ok();
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

app.Run();