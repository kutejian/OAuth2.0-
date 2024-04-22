using Newtonsoft.Json;
using System;
using System.ComponentModel.DataAnnotations;

namespace OAuth20.Lab.Models.ViewModels
{
    public class GithubUserViewModel
    {
        public string Login { get; set; }

        [JsonProperty("avatar_url")]
        [DataType(DataType.ImageUrl)]
        public string AvatarUrl { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("location")]
        public string Location { get; set; }

        [JsonProperty("email")]
        public string Email { get; set; }

        [JsonProperty("html_url")]
        public string HtmlUrl { get; set; }

        [JsonProperty("created_at")]
        public DateTime CreatedAt { get; set; }

        [JsonProperty("updated_at")]
        public DateTime UpdatedAt { get; set; }

        [JsonProperty("two_factor_authentication")]
        public bool TwoFactorAuthentication { get; set; }

        [JsonProperty("plan")]
        public dynamic Plan { get; set; }
    }
}