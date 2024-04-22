using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using OAuth20.Lab.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using OAuth20.Common.Model;
using OAuth20.Common.Models;

namespace OAuth20.Lab.Controllers
{
    // https://developers.google.com/identity/protocols/oauth2/web-server#httprest_1
    public class GoogleController : Controller
    {
        private readonly string _redirectUri;
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly IHttpClientFactory _httpClientFactory;

        public GoogleController(IOptions<GoogleCredential> options, IHttpClientFactory httpClientFactory)
        {
            var credential = options.Value;

            _clientId = credential.ClientId;
            _clientSecret = credential.ClientSecret;
            _redirectUri = credential.RedirectUri;

            _httpClientFactory = httpClientFactory;
        }

        public IActionResult Authorize()
        {
            var uri = "https://accounts.google.com/o/oauth2/v2/auth";

            var param = new Dictionary<string, string>
            {
                { "response_type", "code" },
                { "client_id", _clientId },
                { "redirect_uri",  _redirectUri},
                { "scope", "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile" },
                { "state", "123456" },
                { "access_type", "offline" }
            };

            var requestUri = QueryHelpers.AddQueryString(uri, param);

            return Redirect(requestUri);
        }

        public async Task<IActionResult> Callback([FromQuery] string code, [FromQuery] string state)
        {
            var uri = "https://oauth2.googleapis.com/token";

            var param = new Dictionary<string, string>
            {
                { "client_id", _clientId },
                { "client_secret", _clientSecret },
                { "code", code },
                { "grant_type", "authorization_code" },
                { "redirect_uri",  _redirectUri}
            };

            using var httpClient = _httpClientFactory.CreateClient();

            var requestContent = new FormUrlEncodedContent(param);

            var response = await httpClient.PostAsync(uri, requestContent);
            var responseContent = JsonConvert.DeserializeObject<dynamic>(await response.Content.ReadAsStringAsync());

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException(responseContent);
            }

            string accessToken = Convert.ToString(responseContent!.access_token);

            (string userId, string email) userInfo = DecodeJwt(Convert.ToString(responseContent.id_token));

            if (string.IsNullOrEmpty(accessToken))
            {
                throw new Exception("accessToken is empty");
            }

            HttpContext.Response.Cookies.Append(CookieNames.GoogleAccessToken, accessToken);
            HttpContext.Response.Cookies.Append(CookieNames.GoogleUserId, userInfo.userId);
            HttpContext.Response.Cookies.Append(CookieNames.GoogleEmail, userInfo.email);

            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> Profile()
        {
            if (!HttpContext.Request.Cookies.TryGetValue(CookieNames.GoogleAccessToken, out var accessToken))
            {
                throw new Exception("accessToken is empty");
            }

            if (!HttpContext.Request.Cookies.TryGetValue(CookieNames.GoogleUserId, out var _))
            {
                throw new Exception("google userId is empty");
            }

            const string uri = "https://www.googleapis.com/oauth2/v2/userinfo";

            //var personFields = new List<string> { "names", "emailAddresses", "photos" };

            //var requestUri = QueryHelpers.AddQueryString(uri, new Dictionary<string, string>
            //{
            //    { "personFields", string.Join(',', personFields)}
            //});

            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await httpClient.GetAsync(uri);

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException(response.ReasonPhrase);
            }

            var userInfo = JsonConvert.DeserializeObject<GoogleUserInfo>(
                await response.Content.ReadAsStringAsync());

            return View(userInfo);
        }

        private (string userId, string email) DecodeJwt(string idToken)
        {
            var handler = new JwtSecurityTokenHandler();

            try
            {
                var jwt = handler.ReadJwtToken(idToken); //JWT驗證物件
                if (jwt == null)
                    throw new ArgumentException("Invalid JWT token");

                var idTokens = idToken.Split('.');
                var header = idTokens[0];
                var payload = idTokens[1];
                var signature = idTokens[2];

                var payloadDecoded = Base64UrlEncoder.Decode(payload);

                var payloadJson = JObject.Parse(payloadDecoded);

                return (
                    userId: Convert.ToString(payloadJson["sub"]),
                    email: Convert.ToString(payloadJson["email"])
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine($"msg:{ex.Message}");
                throw new Exception(ex.Message);
            }
        }
    }
}