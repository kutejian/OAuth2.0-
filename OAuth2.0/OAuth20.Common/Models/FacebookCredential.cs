using OAuth20.Common.Model.Interfaces;

namespace OAuth20.Common.Models;

public class FacebookCredential : IOAuth20Credential, IRedirectUri
{
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
    public string RedirectUri { get; set; }
}