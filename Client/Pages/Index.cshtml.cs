using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Client.Pages
{
    public class IndexModel : PageModel
    {
        public string ApiUrl;

        public IndexModel(IConfiguration configuration)
        {
            ApiUrl = configuration["Url"];
        }

        public void OnGet()
        {

        }
    }
}