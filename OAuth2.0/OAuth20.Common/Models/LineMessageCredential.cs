using OAuth20.Common.Model.Interfaces;

namespace OAuth20.Common.Models;

public class LineMessageCredential : IOAuth20Credential
{
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
    public string MyUserId { get; set; }
}