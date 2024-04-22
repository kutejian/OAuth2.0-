using OAuth20.Common.Model.Interfaces;

namespace OAuth20.Common.Models;

public class AzureDevOpsCredential : IOAuth20Credential, IRedirectUri
{
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
    public string RedirectUri { get; set; }
    public string Organization { get; set; }
    public string Project { get; set; }
}