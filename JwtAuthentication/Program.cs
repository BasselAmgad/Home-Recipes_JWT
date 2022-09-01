using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Server.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var securityScheme = new OpenApiSecurityScheme()
{
    Name = "Authorization",
    Type = SecuritySchemeType.ApiKey,
    Scheme = "Bearer",
    BearerFormat = "JWT",
    In = ParameterLocation.Header,
    Description = "Home Recipes API secured with JWT",
};

var securityReq = new OpenApiSecurityRequirement()
{
    {
        new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            {
                Type = ReferenceType.SecurityScheme,
                Id = "Bearer"
            }
        },
        new string[] {}
    }
};

var contact = new OpenApiContact()
{
    Name = "Bassel Amgad",
    Email = "bamgad7@gmail.com",
    Url = new Uri("https://github.com/BasselAmgad")
};

var info = new OpenApiInfo()
{
    Version = "v1",
    Title = "Home Recipes API secured with JWT",
    Description = "Implementing JWT Authentication in Minimal API",
    Contact = contact,
};

// Add services to the container.
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", info);
    o.AddSecurityDefinition("Bearer", securityScheme);
    o.AddSecurityRequirement(securityReq);
});

builder.Services.AddAuthentication(o =>
{
    o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
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

builder.Services.AddCors(options =>
{
    options.AddPolicy(name: "client",
                      policy =>
                      {
                          policy.WithOrigins(builder.Configuration["ClientUrl"])
                                .AllowAnyHeader()
                                .AllowAnyMethod()
                                .AllowCredentials();
                      });
});

builder.Services.AddControllers();
builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddAntiforgery(options => options.HeaderName = "X-XSRF-TOKEN");
builder.Services.AddSingleton<Data>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapPost("/register", async ([FromBody] User newUser) =>
{
    var data = new Data();
    var hasher = new PasswordHasher<User>();
    var usersList = await data.GetUsersAsync();
    if (usersList is null)
        throw new Exception("Could not deserialize users list");
    if (usersList.Find(x => x.UserName == newUser.UserName) != null)
        return Results.BadRequest("username already exists");
    User newRegisteredUser = new User(newUser.UserName, "");
    string hashedPassword = hasher.HashPassword(newRegisteredUser, newUser.Password);
    newRegisteredUser.Password = hashedPassword;
    await data.AddUserAsync(newRegisteredUser);
    return Results.Ok();
});

app.MapPost("/login", [AllowAnonymous] async (User user) =>
{
    Data data = new();
    var passwordHasher = new PasswordHasher<User>();
    var usersList = await data.GetUsersAsync();
    if (usersList is null)
        throw new Exception("Could not deserialize users list");
    var userData = usersList.FirstOrDefault(u => u.UserName == user.UserName);
    if (userData is null)
        return Results.NotFound("User does not exist");
    var verifyPassword = passwordHasher.VerifyHashedPassword(userData, userData.Password, user.Password);
    if (verifyPassword == PasswordVerificationResult.Failed)
        return Results.Unauthorized();
    var issuer = builder.Configuration["Jwt:Issuer"];
    var audience = builder.Configuration["Jwt:Audience"];
    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]));
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    var jwtTokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(builder.Configuration["Jwt:Key"]);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
                new Claim("Id", userData.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            }),
        // the life span of the token needs to be shorter and utilise refresh token to keep the user signedin
        // but since this is a demo app we can extend it to fit our current need
        Expires = DateTime.UtcNow.AddHours(6),
        Audience = audience,
        Issuer = issuer,
        // here we are adding the encryption alogorithim information which will be used to decrypt our token
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
    };
    var token = jwtTokenHandler.CreateToken(tokenDescriptor);
    var jwtToken = jwtTokenHandler.WriteToken(token);
    return Results.Ok(new AuthenticatedResponse { RefreshToken = "", Token = jwtToken, UserName = userData.UserName});
});

app.MapGet("/antiforgery", (IAntiforgery antiforgery, HttpContext context) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    context.Response.Cookies.Append("X-XSRF-TOKEN", tokens.RequestToken!, new CookieOptions { HttpOnly = false });
});

app.MapGet("/recipes",  async (IAntiforgery antiforgery,Data data, HttpContext context) =>
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
});

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

app.UseSwagger();
app.UseSwaggerUI();
app.UseCors("client");
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

