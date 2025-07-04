using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ADTP
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum Method
    {
        [JsonStringEnumMemberName("check")]
        Check,
        [JsonStringEnumMemberName("read")]
        Read,
        [JsonStringEnumMemberName("create")]
        Create,
        [JsonStringEnumMemberName("update")]
        Update,
        [JsonStringEnumMemberName("append")]
        Append,
        [JsonStringEnumMemberName("destroy")]
        Destroy,
        [JsonStringEnumMemberName("auth")]
        Auth
    }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum Version
    {
        [JsonStringEnumMemberName("ADTP/2.0")]
        Adtp2
    }
    
    public class RequestBuilder
    {
        [JsonPropertyName("version")]
        public Version Version { get; set; } = Version.Adtp2;
        [JsonPropertyName("method")]
        public Method Method { get; set; } = Method.Check;
        [JsonPropertyName("headers")]
        // ReSharper disable once MemberCanBePrivate.Global
        public Dictionary<string, string> Headers { get; set; } = new();
        [JsonPropertyName("uri")]
        public string Uri { get; set; } = "";
        [JsonPropertyName("content")]
        public string Content { get; set; } = "";

        public RequestBuilder SetVersion(Version version)
        {
            Version = version;
            return this;
        }

        public RequestBuilder SetMethod(Method method)
        {
            Method = method;
            return this;
        }

        public RequestBuilder AddHeader(string name, string value)
        {
            Headers.Add(name, value);
            return this;
        }

        public RequestBuilder SetUri(string uri)
        {
            Uri = uri;
            return this;
        }

        public RequestBuilder SetContent(string content)
        {
            Content = content;
            return this;
        }

        public string Build()
        {
            return JsonSerializer.Serialize(this);
        }
        
        public static RequestBuilder FromString(string response)
        {
            return JsonSerializer.Deserialize<RequestBuilder>(response);
        }
    }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum Status
    {
        [JsonStringEnumMemberName("switch-protocols")]
        SwitchProtocols,
        [JsonStringEnumMemberName("ok")]
        Ok,
        [JsonStringEnumMemberName("pending")]
        Pending,
        [JsonStringEnumMemberName("redirect")]
        Redirect,
        [JsonStringEnumMemberName("denied")]
        Denied,
        [JsonStringEnumMemberName("bad-request")]
        BadRequest,
        [JsonStringEnumMemberName("unauthorized")]
        Unauthorized,
        [JsonStringEnumMemberName("not-found")]
        NotFound,
        [JsonStringEnumMemberName("too-many-requests")]
        TooManyRequests,
        [JsonStringEnumMemberName("internal-error")]
        InternalError
    }

    public class ResponseBuilder
    {
        [JsonPropertyName("version")]
        public Version Version { get; set; } = Version.Adtp2;

        [JsonPropertyName("status")] 
        public Status Status { get; set; } = Status.Ok;
        [JsonPropertyName("headers")]
        // ReSharper disable once MemberCanBePrivate.Global
        public Dictionary<string, string> Headers { get; set; } = new();
        [JsonPropertyName("content")]
        public string Content { get; set; } = "";
        
        public ResponseBuilder SetVersion(Version version)
        {
            Version = version;
            return this;
        }

        public ResponseBuilder SetStatus(Status status)
        {
            Status = status;
            return this;
        }
        
        public ResponseBuilder AddHeader(string name, string value)
        {
            Headers.Add(name, value);
            return this;
        }
        
        public ResponseBuilder SetContent(string content)
        {
            Content = content;
            return this;
        }

        public string Build()
        {
            return JsonSerializer.Serialize(this);
        }

        public static ResponseBuilder FromString(string response)
        {
            return JsonSerializer.Deserialize<ResponseBuilder>(response);
        }
    }
}