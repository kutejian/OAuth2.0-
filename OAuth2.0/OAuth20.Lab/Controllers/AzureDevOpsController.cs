using System.Net.Http.Headers;
using System.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OAuth20.Common.Models;
using OAuth20.Lab.Models;

namespace OAuth20.Lab.Controllers;

public class AzureDevOpsController : Controller
{
    private readonly string _redirectUri;

    private readonly string _clientId;
    private readonly string _clientSecret;
    private readonly string _organization;
    private readonly string _project;
    private readonly IHttpClientFactory _httpClientFactory;
    

    public AzureDevOpsController (IOptions<AzureDevOpsCredential> options, IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
        
        _clientId = options.Value.ClientId;
        _clientSecret = options.Value.ClientSecret;
        _redirectUri = options.Value.RedirectUri;
        
        _organization = options.Value.Organization;
        _project = options.Value.Project;
    }

    public IActionResult Authorize ()
    {
        // https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth?view=azure-devops#register-your-app
        const string uri = "https://app.vssps.visualstudio.com/oauth2/authorize";
        var param = new Dictionary<string, string>
        {
            { "response_type", "Assertion" },
            { "client_id", _clientId },
            { "redirect_uri", _redirectUri },
            {
                "scope", "vso.extension.data_write vso.extension_manage vso.gallery_manage vso.machinegroup_manage vso.packaging_manage vso.pipelineresources_manage vso.project_manage vso.release_manage vso.securefiles_manage vso.serviceendpoint_manage vso.symbols_manage vso.taskgroups_manage vso.variablegroups_manage"
            }
        };

        var requestUri = QueryHelpers.AddQueryString(uri, param);

        return Redirect(requestUri);
    }

    public async Task<IActionResult> Callback ([FromQuery] string code, [FromQuery] string state)
    {
        const string uri = "https://app.vssps.visualstudio.com/oauth2/token";
        var param = new Dictionary<string, string>
        {
            { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
            { "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer" },
            { "client_assertion", HttpUtility.UrlEncode(_clientSecret) },
            { "assertion", HttpUtility.UrlEncode(code) },
            { "redirect_uri", _redirectUri },
            { "state", state }
        };

        using var httpClient = _httpClientFactory.CreateClient();
        var requestContent = new FormUrlEncodedContent(param);

        var response = await httpClient.PostAsync(uri, requestContent);

        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync();
            throw new Exception(errorContent);
        }

        var content = await response.Content.ReadAsStringAsync();
        var json = JObject.Parse(content);
        var accessToken = json["access_token"].Value<string>();
        var refreshToken = json["refresh_token"].Value<string>();
        var expiresIn = json["expires_in"].Value<int>();
        var tokenType = json["token_type"].Value<string>();
        
        HttpContext.Response.Cookies.Append(CookieNames.AzureDevopsAccessToken, accessToken);
        
        return RedirectToAction("Index", "Home");
    }

    public async Task<IActionResult> TaskGroups ()
    {
        if (!HttpContext.Request.Cookies.TryGetValue(CookieNames.AzureDevopsAccessToken, out var accessToken))
        {
            throw new Exception("Access token not found");
        }
        
        var uri = $"https://dev.azure.com/{_organization}/{_project}/_apis/distributedtask/taskgroups?api-version=7.0";
        
        var response = await PostAzureApiAsync(accessToken, uri);

        var result = JsonConvert.DeserializeObject<dynamic>(await response.Content.ReadAsStringAsync());
        return View(result);
    }

    public async Task<IActionResult> VariableGroups ()
    {
        if (!HttpContext.Request.Cookies.TryGetValue(CookieNames.AzureDevopsAccessToken, out var accessToken))
        {
            throw new Exception("Access token not found");
        }
        
        var uri = $"https://dev.azure.com/{_organization}/{_project}/_apis/distributedtask/variablegroups?api-version=7.0";
        
        var response = await PostAzureApiAsync(accessToken, uri);

        var result = JsonConvert.DeserializeObject<dynamic>(await response.Content.ReadAsStringAsync());
        return View(result);
        
    }

    private async Task<HttpResponseMessage> PostAzureApiAsync (string accessToken, string uri)
    {
        using var httpClient = _httpClientFactory.CreateClient();
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var response = await httpClient.GetAsync(uri);

        if (!response.IsSuccessStatusCode)
        {
            throw new Exception(await response.Content.ReadAsStringAsync());
        }

        return response;
    }
}