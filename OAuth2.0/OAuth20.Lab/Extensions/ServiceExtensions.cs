using OAuth20.Common.Model;
using OAuth20.Common.Models;

namespace OAuth20.Lab.Extensions;

public static class ServiceExtensions
{
    public static void AddConfigures (this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<LineNotifyCredential>(configuration.GetSection("Credentials:LineNotify"));
        services.Configure<LineMessageCredential>(configuration.GetSection("Credentials:LineMessage"));
        services.Configure<LineLoginCredential>(configuration.GetSection("Credentials:LineLogin"));
        services.Configure<FacebookCredential>(configuration.GetSection("Credentials:Facebook"));
        services.Configure<GoogleCredential>(configuration.GetSection("Credentials:Google"));
        services.Configure<GithubCredential>(configuration.GetSection("Credentials:Github"));
        services.Configure<AzureDevOpsCredential>(configuration.GetSection("Credentials:AzureDevOps"));
        
    }
}