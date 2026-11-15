using Lagrange.Core.Utility.Extension;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Lagrange.Core.Common;
using Lagrange.Core.Utility.Sign;
using Lagrange.OneBot.Utility.Fallbacks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Lagrange.OneBot.Utility;

public class OneBotSigner : SignProvider
{
    private readonly IConfiguration _configuration;

    private readonly ILogger<OneBotSigner> _logger;

    private readonly string? _signServer;

    private readonly string? _signToken;

    private readonly string? _signVersion;

    private readonly HttpClient _client;

    private readonly BotAppInfo? _info;

    private readonly string _qua;

    private readonly string _guid;

    private readonly long _uin;

    private readonly bool _isLinuxQua;

    private readonly bool _isMacQua;

    public OneBotSigner(IConfiguration config, ILogger<OneBotSigner> logger)
    {
        _configuration = config;
        _logger = logger;

        // Lagrange V2 Sign API (ported from acidify LagrangeUrlSignProvider)
        _signServer = config["SignServerUrl"];
        _signToken = config["SignServerToken"];
        _signVersion = config["SignServerVersion"];
        string? signProxyUrl = config["SignProxyUrl"]; // Only support HTTP proxy

        _client = new HttpClient(handler: new HttpClientHandler
        {
            Proxy = string.IsNullOrEmpty(signProxyUrl) ? null : new WebProxy()
            {
                Address = new Uri(signProxyUrl),
                BypassProxyOnLocal = false,
                UseDefaultCredentials = false,
            },
        }, disposeHandler: true);

        if (!string.IsNullOrEmpty(_signToken))
            _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _signToken);

        if (string.IsNullOrEmpty(_signServer)) logger.LogWarning("Signature Service is not available, login may be failed");

        _info ??= GetAppInfo();

        _qua = "V1_" + (_info.Os switch
        {
            "Windows" => "WIN",
            "Mac" => "MAC",
            "Linux" => "LNX",
            _ => throw new Exception("Unknown OS")
        }) + $"_NQ_{_info.CurrentVersion.Replace('-', '_')}_GW_B";
        _isLinuxQua = _qua.StartsWith("V1_LNX_");
        _isMacQua = _qua.StartsWith("V1_MAC_");

        _guid = config["SignServerGuid"] ?? Guid.NewGuid().ToByteArray().Hex(true);
        _uin = config.GetValue("Account:Uin", 0u);
    }

    public override byte[]? Sign(string cmd, uint seq, byte[] body, [UnscopedRef] out byte[]? e, [UnscopedRef] out string? t)
    {
        e = null;
        t = null;

        if (_isLinuxQua && !CommandWhitelist.LinuxCommandWhitelist.Contains(cmd)) return null;
        if (_isMacQua && !CommandWhitelist.MacCommandWhitelist.Contains(cmd)) return null;
        if (_signServer == null) throw new Exception("Sign server is not configured");

        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri($"{GetSignBaseUrl()}/api/sign/sec-sign"),
            Content = JsonContent.Create(new JsonObject
            {
                { "command", cmd },
                { "seq", seq },
                { "body", Convert.ToHexString(body).ToLowerInvariant() },
                { "uin", _uin },
                { "guid", _guid },
                { "qua", _qua },
            })
        };

        using var message = _client.Send(request);
        if (message.StatusCode != HttpStatusCode.OK) throw new Exception($"Signer server returned a {message.StatusCode}");
        var json = JsonDocument.Parse(message.Content.ReadAsStream()).RootElement;

        int code = json.TryGetProperty("code", out var codeJson) ? codeJson.GetInt32() : 0;
        if (code != 0)
            throw new Exception(json.TryGetProperty("message", out var msgJson) ? msgJson.GetString() : $"Signer server returned code {code}");
        if (!json.TryGetProperty("value", out var valueJson) || valueJson.ValueKind == JsonValueKind.Null)
            throw new Exception("Signer server returned an empty value");

        var secSign = valueJson.GetProperty("sec_sign").GetString() ?? throw new Exception("Signer server returned an empty sign");
        var secToken = valueJson.GetProperty("sec_token").GetString();
        var secExtra = valueJson.GetProperty("sec_extra").GetString();

        e = secExtra != null ? Convert.FromHexString(secExtra) : [];
        t = secToken != null ? Encoding.UTF8.GetString(Convert.FromHexString(secToken)) : "";
        return Convert.FromHexString(secSign);
    }

    /// <summary>
    /// Sign server base URL: when <c>SignServerVersion</c> is set, a <c>/v/{version}</c> segment is
    /// appended to <c>SignServerUrl</c> so the gateway routes to the matching backend.
    /// </summary>
    private string GetSignBaseUrl()
    {
        string baseUrl = _signServer!.TrimEnd('/');
        return string.IsNullOrEmpty(_signVersion) ? baseUrl : $"{baseUrl}/v/{_signVersion.Trim('/')}";
    }

    public BotAppInfo GetAppInfo()
    {
        if (_info != null) return _info;

        return FallbackAsync<BotAppInfo>.Create()
            .Add(async token =>
            {
                try { return await _client.GetFromJsonAsync<BotAppInfo>($"{GetSignBaseUrl()}/api/sign/appinfo", token); }
                catch { return null; }
            })
            .Add(token =>
            {
                string path = _configuration["ConfigPath:AppInfo"] ?? "appinfo.json";

                if (!File.Exists(path)) return Task.FromResult(null as BotAppInfo);

                try { return Task.FromResult(JsonSerializer.Deserialize<BotAppInfo>(File.ReadAllText(path))); }
                catch { return Task.FromResult(null as BotAppInfo); }
            })
            .ExecuteAsync(token => Task.FromResult(
                BotAppInfo.ProtocolToAppInfo[_configuration["Account:Protocol"] switch
                {
                    "Windows" => Protocols.Windows,
                    "MacOs" => Protocols.MacOs,
                    _ => Protocols.Linux,
                }]
            ))
            .Result;
    }
}
