
using Microsoft.AspNetCore.Antiforgery;

var builder = WebApplication.CreateBuilder(args);

using IHost host = Host.CreateDefaultBuilder(args).Build();
IConfiguration config = host.Services.GetRequiredService<IConfiguration>();

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
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAntiforgery(options => options.HeaderName = "X-XSRF-TOKEN");

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();
app.UseHttpsRedirection();
app.UseCors("localhostOnly");

app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
    options.RoutePrefix = string.Empty;
});

app.MapGet("antiforgery", (IAntiforgery antiforgery, HttpContext context) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    context.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!, new CookieOptions { HttpOnly = false });
});

app.MapGet("recipes", async (HttpContext context, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        Data data = new(app.Logger);
        var recipes = await data.GetRecipesAsync();
        return Results.Ok(recipes);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

app.MapGet("/recipes/{id}", async (IAntiforgery antiforgery, HttpContext context, Guid id) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        Data data = new(app.Logger);
        Recipe recipe = await data.GetRecipeAsync(id);
        return Results.Ok(recipe);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }

});

app.MapPost("/recipes", async (IAntiforgery antiforgery, HttpContext context, Recipe recipe) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        Data data = new(app.Logger);
        recipe.Id = Guid.NewGuid();
        await data.AddRecipeAsync(recipe);
        return Results.Created($"/recipes/{recipe.Id}", recipe);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }

});

app.MapPut("/recipes/{id}", async (IAntiforgery antiforgery, HttpContext context, Guid id, Recipe newRecipe) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        Data data = new(app.Logger);
        var updatedRecipe = await data.EditRecipeAsync(id, newRecipe);
        return Results.Ok(updatedRecipe);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }

});

app.MapDelete("/recipes/{id}", async (IAntiforgery antiforgery, HttpContext context, Guid id) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        Data data = new(app.Logger);
        await data.RemoveRecipeAsync(id);
        return Results.Ok();
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }

});

app.MapGet("/categories", async (IAntiforgery antiforgery, HttpContext context) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        Data data = new(app.Logger);
        var categories = await data.GetAllCategoriesAsync();
        return Results.Ok(categories);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

app.MapPost("/categories", async (IAntiforgery antiforgery, HttpContext context, string category) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        Data data = new(app.Logger);
        await data.AddCategoryAsync(category);
        return Results.Created($"/categories/{category}", category);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

app.MapPut("/categories", async (IAntiforgery antiforgery, HttpContext context, string category, string newCategory) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        Data data = new(app.Logger);
        await data.EditCategoryAsync(category, newCategory);
        return Results.Ok($"Category ({category}) updated to ({newCategory})");
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

app.MapDelete("/categories", async (IAntiforgery antiforgery, HttpContext context, string category) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        Data data = new(app.Logger);
        await data.RemoveCategoryAsync(category);
        return Results.Ok();
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

app.MapPost("recipes/category", async (IAntiforgery antiforgery, HttpContext context, Guid id, string category) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        Data data = new(app.Logger);
        await data.AddCategoryToRecipeAsync(id, category);
        return Results.Created($"recipes/category/{category}", category);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

app.MapDelete("recipes/category", async (IAntiforgery antiforgery, HttpContext context, Guid id, string category) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        Data data = new(app.Logger);
        await data.RemoveCategoryFromRecipeAsync(id, category);
        return Results.Ok();
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

app.Run();