using Server.Models;
using System.Text.Json;

class Data
{
    private readonly ILogger _logger;
    private List<Recipe> _recipes { get; set; } = new();
    private List<string> _categories { get; set; } = new();
    private List<User> _users { get; set; } = new();
    private string _usersFilePath;
    private string _recipesFilePath;
    private string _categoriesFilePath;
    public Data(ILogger logger)
    {
        _recipesFilePath = Path.Combine(Environment.CurrentDirectory, "Data", "Recipes.json");
        _categoriesFilePath = Path.Combine(Environment.CurrentDirectory, "Data", "Categories.json");
        _usersFilePath = Path.Combine(Environment.CurrentDirectory, "Data", "Users.json");
        _logger = logger;
    }

    public async Task<List<User>> GetUsersAsync()
    {
        await LoadDataAsync();
        return _users;
    }
    public async Task<List<Recipe>> GetRecipesAsync()
    {
        await LoadDataAsync();
        return _recipes;
    }

    public async Task AddUserAsync(User user)
    {
        await LoadDataAsync();
        _users.Add(user);
        await SaveDataAsync();
    }

    public async Task AddRecipeAsync(Recipe r)
    {
        await LoadDataAsync();
        _recipes.Add(r);
        await SaveDataAsync();
    }

    public async Task<Recipe> GetRecipeAsync(Guid id)
    {
        await LoadDataAsync();
        var recipe = _recipes.Find(r => r.Id == id);
        if (recipe == null)
            recipe = new Recipe();
        return recipe;
    }

    public async Task RemoveRecipeAsync(Guid id)
    {
        await LoadDataAsync();
        var recipe = await GetRecipeAsync(id);
        _recipes.Remove(recipe);
        await SaveDataAsync();
    }

    public async Task<Recipe> EditRecipeAsync(Guid id, Recipe newRecipe)
    {
        await LoadDataAsync();
        var recipe = await GetRecipeAsync(id);
        recipe.Title = newRecipe.Title;
        recipe.Ingredients = newRecipe.Ingredients;
        recipe.Instructions = newRecipe.Instructions;
        recipe.Categories = newRecipe.Categories;
        await SaveDataAsync();
        return recipe;
    }

    public async Task EditTitleAsync(Guid id, string newTitle)
    {
        await LoadDataAsync();
        var recipe = await GetRecipeAsync(id);
        recipe.Title = newTitle;
        await SaveDataAsync();
    }

    public async Task EditIngredientsAsync(Guid id, string newIngredients)
    {
        await LoadDataAsync();
        var recipe = await GetRecipeAsync(id);
        recipe.Ingredients = newIngredients;
        await SaveDataAsync();
    }

    public async Task EditInstructionsAsync(Guid id, string newInstructions)
    {
        await LoadDataAsync();
        var recipe = await GetRecipeAsync(id);
        recipe.Instructions = newInstructions;
        await SaveDataAsync();
    }

    public async Task EditCategoryAsync(Guid id, string category, string newCategory)
    {
        await LoadDataAsync();
        await RemoveCategoryFromRecipeAsync(id, category);
        await AddCategoryToRecipeAsync(id, newCategory);
        await SaveDataAsync();
    }

    public async Task<List<string>> GetCategoriesAsync()
    {
        await LoadDataAsync();
        _categories.Sort();
        return _categories;
    }

    public async Task AddCategoryAsync(string category)
    {
        await LoadDataAsync();
        if (!_categories.Contains(category))
            _categories.Add(category);
        await SaveDataAsync();
    }

    public async Task EditCategoryAsync(string category, string newCategory)
    {
        await LoadDataAsync();
        if (_categories.Contains(category))
        {
            foreach (var recipe in _recipes.Where(r => r.Categories.Contains(category)))
            {
                recipe.Categories.Remove(category);
                recipe.Categories.Add(newCategory);
            }
            _categories.Remove(category);
            _categories.Add(newCategory);
        }
        await SaveDataAsync();
    }

    public async Task RemoveCategoryAsync(string category)
    {
        await LoadDataAsync();
        if (_categories.Contains(category))
        {
            _categories.Remove(category);
            var recipes = _recipes.Where(r => r.Categories.Contains(category)).ToList();
            foreach (var recipe in recipes)
                recipe.Categories.Remove(category);
        }
        await SaveDataAsync();
    }

    public async Task AddCategoryToRecipeAsync(Guid id, string category)
    {
        await LoadDataAsync();
        if (_categories.Contains(category))
        {
            var recipe = await GetRecipeAsync(id);
            recipe.Categories.Add(category);
        }
        await SaveDataAsync();
    }

    public async Task RemoveCategoryFromRecipeAsync(Guid id, string category)
    {
        var recipe = await GetRecipeAsync(id);
        recipe.Categories.Remove(category);
        await SaveDataAsync();
    }

    public async Task LoadDataAsync()
    {
        try
        {
            if (!File.Exists(_recipesFilePath))
            {
                _recipes = new List<Recipe>();
                await File.WriteAllTextAsync(_recipesFilePath, JsonSerializer.Serialize(_recipes));
            }
            if (!File.Exists(_categoriesFilePath))
            {
                _categories = new List<string>();
                await File.WriteAllTextAsync(_categoriesFilePath, JsonSerializer.Serialize(_categories));
            }
            if (!File.Exists(_usersFilePath))
            {
                _users = new List<User>();
                await File.WriteAllTextAsync(_categoriesFilePath, JsonSerializer.Serialize(_users));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(DateTime.Now.ToString(), "- Error while attempting to create the files: ", ex.ToString());
        }
        try
        {
            using (StreamReader r = new(_recipesFilePath))
            {
                var data = await r.ReadToEndAsync();
                var json = JsonSerializer.Deserialize<List<Recipe>>(data);
                if (json != null)
                    _recipes = json;
            }
            using (StreamReader r = new(_categoriesFilePath))
            {
                var data = await r.ReadToEndAsync();
                var json = JsonSerializer.Deserialize<List<string>>(data);
                if (json != null)
                    _categories = json;
            }
            using (StreamReader r = new(_usersFilePath))
            {
                var data = await r.ReadToEndAsync();
                var json = JsonSerializer.Deserialize<List<User>>(data);
                if (json != null)
                    _users = json;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(DateTime.Now.ToString(), "- Error while attempting to save the data to the files: ", ex.ToString());
        }

    }

    public async Task SaveDataAsync()
    {
        try
        {
            await File.WriteAllTextAsync(_recipesFilePath, JsonSerializer.Serialize(_recipes));
            await File.WriteAllTextAsync(_categoriesFilePath, JsonSerializer.Serialize(_categories));
            await File.WriteAllTextAsync(_usersFilePath, JsonSerializer.Serialize(_users));
        }
        catch (Exception ex)
        {
            _logger.LogError(DateTime.Now.ToString(), "- Error while attempting to save files: ", ex.ToString());
        }
    }
}