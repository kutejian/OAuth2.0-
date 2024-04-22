namespace OAuth20.Common.Model.Interfaces;

public interface IOAuth20Credential
{
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
}

public interface IRedirectUri
{
    public string RedirectUri { get; set; }
}