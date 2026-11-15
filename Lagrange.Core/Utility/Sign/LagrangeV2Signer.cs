using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Lagrange.Core.Utility.Sign;

/// <summary>
/// Signer ported from acidify's <c>LagrangeUrlSignProvider</c> (Lagrange V2 Sign API).
/// POST {url}/api/sign/sec-sign with Bearer auth, body containing cmd/seq/body/uin/guid/qua.
/// </summary>
public class LagrangeV2Signer : SignProvider
{
    private readonly string _url;
    private readonly string _token;
    private readonly long _uin;
    private readonly string _guid;
    private readonly string _qua;
    private readonly bool _isLinuxQua;
    private readonly bool _isMacQua;

    private readonly HttpClient _client = new();

    public LagrangeV2Signer(string url, string token, long uin, string guid, string qua)
    {
        _url = url.TrimEnd('/');
        _token = token;
        _uin = uin;
        _guid = guid;
        _qua = qua;
        _isLinuxQua = qua.StartsWith("V1_LNX_");
        _isMacQua = qua.StartsWith("V1_MAC_");

        _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
    }

    public override byte[]? Sign(string cmd, uint seq, byte[] body, out byte[]? e, out string? t)
    {
        e = null;
        t = null;

        if (_isLinuxQua && !CommandWhitelist.LinuxCommandWhitelist.Contains(cmd)) return null;
        if (_isMacQua && !CommandWhitelist.MacCommandWhitelist.Contains(cmd)) return null;

        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri($"{_url}/api/sign/sec-sign"),
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
        if (message.StatusCode != HttpStatusCode.OK)
            throw new Exception($"Signer server returned a {message.StatusCode}");

        var json = JsonDocument.Parse(message.Content.ReadAsStream()).RootElement;
        int code = json.TryGetProperty("code", out var codeJson) ? codeJson.GetInt32() : 0;
        if (code != 0)
            throw new Exception(json.TryGetProperty("message", out var msgJson) ? msgJson.GetString() : $"Signer server returned code {code}");
        if (!json.TryGetProperty("value", out var valueJson) || valueJson.ValueKind == JsonValueKind.Null)
            throw new Exception("Signer server returned an empty value");

        var secSign = valueJson.GetProperty("sec_sign").GetString() ?? throw new Exception("Signer server returned an empty sign");
        var secToken = valueJson.GetProperty("sec_token").GetString();
        var secExtra = valueJson.GetProperty("sec_extra").GetString();

        e = secExtra != null ? Convert.FromHexString(secExtra) : Array.Empty<byte>();
        t = secToken != null ? Encoding.UTF8.GetString(Convert.FromHexString(secToken)) : "";
        return Convert.FromHexString(secSign);
    }
}
