using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

using Newtonsoft.Json;

using OAuth20.Lab.Models;
using OAuth20.Lab.Models.ViewModels;
using System.Net.Http.Headers;
using OAuth20.Common.Model;
using OAuth20.Common.Models;

namespace OAuth20.Lab.Controllers
{
    public class LineLoginController : Controller
    {
        private const string AuthorizeUri = "https://access.line.me/oauth2/v2.1/authorize";

        private readonly string _redirectUri;
        private readonly string _clientId;
        private readonly string _clientSecret;

        private readonly IHttpClientFactory _httpClientFactory;

        public LineLoginController(IHttpClientFactory httpClientFactory, IOptions<LineLoginCredential> options)
        {
            var credential = options.Value;

            _clientId = credential.ClientId;
            _clientSecret = credential.ClientSecret;
            _redirectUri = credential.RedirectUri;

            _httpClientFactory = httpClientFactory;
        }

        public IActionResult Authorize()
        {
            var param = new Dictionary<string, string>
            {
                { "response_type", "code" },
                { "client_id", _clientId },
                { "redirect_uri",  _redirectUri},
                { "scope", "profile openid email" },
                { "state", "123456" }
            };

            var requestUri = QueryHelpers.AddQueryString(AuthorizeUri, param);

            return Redirect(requestUri);
        }

        public async Task<IActionResult> Callback([FromQuery] string code, [FromQuery] string state)
        {
            var param = new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "redirect_uri",  _redirectUri},
                { "client_id", _clientId },
                { "client_secret", _clientSecret }
            };

            var url = "https://api.line.me/oauth2/v2.1/token";
            var content = new FormUrlEncodedContent(param);

            using var httpClient = _httpClientFactory.CreateClient();
            var response = await httpClient.PostAsync(url, content);

            if (!response.IsSuccessStatusCode)
            {
                var message = await response.Content.ReadAsStringAsync();
                throw new HttpRequestException($"{response.StatusCode}, {message}");
            }

            var responseContent = JsonConvert.DeserializeObject<dynamic>(
                (await response.Content.ReadAsStringAsync()));

            string accessToken = Convert.ToString(responseContent!.access_token);
            string idToken = Convert.ToString(responseContent.id_token);

            if (!string.IsNullOrWhiteSpace(accessToken))
                HttpContext.Response.Cookies.Append(CookieNames.LineLoginAccessToken, accessToken);

            if (!string.IsNullOrWhiteSpace(idToken))
                HttpContext.Response.Cookies.Append(CookieNames.LineLoginIdToken, idToken);

            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> Profile()
        {
            var url = "https://api.line.me/v2/profile";

            var accessToken = HttpContext.Request.Cookies[CookieNames.LineLoginAccessToken];
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                return RedirectToAction("Authorize");
            }

            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var response = await httpClient.GetAsync(url);

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"{response.StatusCode}, {await response.Content.ReadAsStringAsync()}");
            }

            var lineProfile = JsonConvert.DeserializeObject<LineProfile>(
                await response.Content.ReadAsStringAsync());

            return View(new LineProfileViewModel
            {
                LineProfile = lineProfile,
                IdToken = HttpContext.Request.Cookies[CookieNames.LineLoginIdToken]
            });
        }
    }
}