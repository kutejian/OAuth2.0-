using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

using OAuth20.Lab.Models;
using OAuth20.Common.Model;
using OAuth20.Common.Models;

namespace OAuth20.Lab.Controllers
{
    public class FacebookController : Controller
    {
        private readonly string _redirectUri;

        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly IHttpClientFactory _httpClientFactory;

        public FacebookController(IOptions<FacebookCredential> options, IHttpClientFactory httpClientFactory)
        {
            var credential = options.Value;

            _clientId = credential.ClientId;
            _clientSecret = credential.ClientSecret;
            _redirectUri = credential.RedirectUri;
            _httpClientFactory = httpClientFactory;
        }

        public IActionResult Authorize()
        {
            const string uri = "https://www.facebook.com/v14.0/dialog/oauth";
            var param = new Dictionary<string, string>
            {
                { "client_id", _clientId },
                { "redirect_uri",  _redirectUri},
                { "state", "123456" }
            };

            var requestUri = QueryHelpers.AddQueryString(uri, param);

            return Redirect(requestUri);
        }

        public async Task<IActionResult> Callback(string code)
        {
            const string uri = "https://graph.facebook.com/v14.0/oauth/access_token";

            using var httpClient = _httpClientFactory.CreateClient();

            var param = new Dictionary<string, string>
            {
                { "client_id", _clientId },
                { "redirect_uri",  _redirectUri},
                { "client_secret", _clientSecret },
                { "code", code }
            };

            var requestUri = QueryHelpers.AddQueryString(uri, param);

            var response = await httpClient.GetAsync(requestUri);
            var content = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"Request is failed. {response.StatusCode}, {content}");
            }

            string accessToken = Convert.ToString(
                JsonConvert.DeserializeObject<dynamic>(content)!.access_token);

            if (string.IsNullOrWhiteSpace(accessToken))
            {
                throw new ArgumentNullException($"access_token is empty");
            }

            HttpContext.Response.Cookies.Append(CookieNames.FacebookAccessToken, accessToken);
            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> UserData()
        {
            if (!HttpContext.Request.Cookies.TryGetValue(CookieNames.FacebookAccessToken, out var accessToken))
            {
                throw new ArgumentNullException($"access_token is empty");
            }

            var userId = await GetUserId(accessToken);

            var uri = $"https://graph.facebook.com/{userId}";

            var param = new Dictionary<string, string>
            {
                ["fields"] = "id,name,email,picture",
                ["access_token"] = accessToken
            };

            var requestUri = QueryHelpers.AddQueryString(uri, param);

            using var httpClient = _httpClientFactory.CreateClient();

            var response = await httpClient.GetAsync(requestUri);
            var content = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"Request is failed. {response.StatusCode}, {content}");
            }

            return View(JsonConvert.DeserializeObject<dynamic>(content));
        }

        private async Task<string> GetUserId(string accessToken)
        {
            if (HttpContext.Request.Cookies.TryGetValue(CookieNames.FacebookUserId, out var userId))
            {
                return userId;
            }

            const string uri = "https://graph.facebook.com/me";

            var param = new Dictionary<string, string>
            {
                ["access_token"] = accessToken
            };

            var requestUri = QueryHelpers.AddQueryString(uri, param);

            using var httpClient = _httpClientFactory.CreateClient();
            var response = await httpClient.GetAsync(requestUri);
            var content = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"Request is failed. {response.StatusCode}, {content}");
            }

            userId = JsonConvert.DeserializeObject<dynamic>(content)!.id;

            HttpContext.Response.Cookies.Append(CookieNames.FacebookUserId, userId);

            return userId;
        }
    }
}