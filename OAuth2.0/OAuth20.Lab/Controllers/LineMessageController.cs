using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

using OAuth20.Lab.Models;
using System.Net.Http.Headers;
using System.Text;
using OAuth20.Common.Model;
using OAuth20.Common.Models;

namespace OAuth20.Lab.Controllers
{
    public class LineMessageController : Controller
    {
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly LineMessageCredential _credential;
        private readonly IHttpClientFactory _httpClientFactory;

        public LineMessageController(IHttpClientFactory httpClientFactory, IOptions<LineMessageCredential> options)
        {
            _credential = options.Value;
            _clientId = _credential.ClientId;
            _clientSecret = _credential.ClientSecret;
            _httpClientFactory = httpClientFactory;
        }

        public async Task<IActionResult> Authorize()
        {
            var uri = "https://api.line.me/v2/oauth/accessToken";

            var param = new Dictionary<string, string>()
            {
                { "grant_type", "client_credentials" },
                { "client_id", _clientId },
                { "client_secret",  _clientSecret}
            };

            using var httpClient = _httpClientFactory.CreateClient();
            var response = await httpClient.PostAsync(uri, new FormUrlEncodedContent(param));

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"{response.StatusCode}, {await response.Content.ReadAsStringAsync()}");
            }

            var content = await response.Content.ReadAsStringAsync();

            string accessToken = JsonConvert.DeserializeObject<dynamic>(content)!.access_token;

            if (string.IsNullOrEmpty(accessToken))
            {
                return BadRequest("access_token is empty");
            }

            HttpContext.Response.Cookies.Append(CookieNames.LineMessageAccessToken, accessToken);

            return RedirectToAction("Index", "Home");
        }

        public IActionResult SendPushMessage()
        {
            return View();
        }

        [HttpPost("SendMessage")]
        public async Task<IActionResult> SendMessage(string message)
        {
            // TODO: 建立 webhook 去擷取 userId
            var json = new
            {
                to = _credential.MyUserId,
                messages = new List<dynamic>
                {
                    new { type = "text", text = message }
                }
            };

            using var httpClient = _httpClientFactory.CreateClient();

            if (!HttpContext.Request.Cookies.TryGetValue(CookieNames.LineMessageAccessToken, out var cookie))
            {
                throw new ArgumentNullException($"cookie is empty");
            }

            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", cookie);

            var response = await httpClient.PostAsync(
                "https://api.line.me/v2/bot/message/push",
                new StringContent(JsonConvert.SerializeObject(json), Encoding.UTF8, "application/json"));

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException(response.ReasonPhrase);
            }

            var _ = await response.Content.ReadAsStringAsync();

            return RedirectToAction("Index", "Home");
        }
    }
}