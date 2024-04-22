using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

using Newtonsoft.Json;

using OAuth20.Lab.Models;
using System.Net.Http.Headers;
using OAuth20.Common.Model;
using OAuth20.Common.Models;

namespace OAuth20.Lab.Controllers
{
    public class LineNotifyController : Controller
    {
        private const string AuthorizeUri = "https://notify-bot.line.me/oauth/authorize";

        private readonly LineNotifyCredential _lineNotify;
        private readonly string _redirectUri;
        private readonly IHttpClientFactory _httpClientFactory;

        public LineNotifyController(IOptions<LineNotifyCredential> options, IHttpClientFactory httpClientFactory)
        {
            _lineNotify = options.Value;
            _redirectUri = _lineNotify.RedirectUri;
            _httpClientFactory = httpClientFactory;
        }

        public IActionResult Authorize()
        {
            var param = new Dictionary<string, string>
            {
                { "response_type", "code" },
                { "client_id", _lineNotify.ClientId },
                { "redirect_uri",  _redirectUri},
                { "scope", "notify" },
                { "state", "123456" }
            };

            var requestUri = QueryHelpers.AddQueryString(AuthorizeUri, param);

            return Redirect(requestUri);
        }

        public async Task<IActionResult> Callback([FromQuery] string code, [FromQuery] string state)
        {
            var url = "https://notify-bot.line.me/oauth/token";

            var param = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = _redirectUri,
                ["client_id"] = _lineNotify.ClientId,
                ["client_secret"] = _lineNotify.ClientSecret
            };

            using var httpClient = _httpClientFactory.CreateClient();
            var content = new FormUrlEncodedContent(param);
            var response = await httpClient.PostAsync(url, content);

            if (!response.IsSuccessStatusCode)
            {
                var message = await response.Content.ReadAsStringAsync();
                throw new HttpRequestException($"{response.StatusCode}, {message}");
            }

            var responseContent = JsonConvert.DeserializeObject<dynamic>(
                (await response.Content.ReadAsStringAsync()));

            string accessToken = Convert.ToString(responseContent!.access_token);

            if (!string.IsNullOrWhiteSpace(accessToken))
                HttpContext.Response.Cookies.Append(CookieNames.LineNotifyAccessToken, accessToken);

            return RedirectToAction("Index", "Home");
        }

        public IActionResult Notify()
        {
            return View();
        }

        [HttpPost("PostNotify")]
        public async Task<IActionResult> PostNotify(string message)
        {
            if (!HttpContext.Request.Cookies.TryGetValue(CookieNames.LineNotifyAccessToken, out var accessToken))
                throw new ArgumentException("cannot get accessToken from Cookie");

            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var content = new FormUrlEncodedContent(new Dictionary<string, string> { ["Message"] = message });
            var response = await httpClient.PostAsync("https://notify-api.line.me/api/notify", content);

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"{response.StatusCode}, {await response.Content.ReadAsStringAsync()}");
            }

            return RedirectToAction("Index", "Home");
        }
    }
}