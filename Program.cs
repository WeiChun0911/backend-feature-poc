using System.Net;
using System.Runtime.InteropServices;
using System.Collections.Concurrent;
using System.Buffers;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Connections.Features;

var builder = WebApplication.CreateBuilder(args);
var tlsFingerprints = new ConcurrentDictionary<string, TlsFingerprint>();
var requireGoogleAuth = builder.Configuration.GetValue<bool>("Authentication:RequireGoogleAuth");
var tcpCaptureEnabled = builder.Configuration.GetValue<bool>("TcpCapture:Enabled");
var googleClientId = builder.Configuration["Authentication:Google:ClientId"];
var googleClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];

if (requireGoogleAuth && (string.IsNullOrWhiteSpace(googleClientId) || string.IsNullOrWhiteSpace(googleClientSecret)))
    throw new InvalidOperationException("Google OAuth client credentials are required when Authentication:RequireGoogleAuth is enabled.");

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.Cookie.Name = "BackendFeaturePoc.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    })
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = "https://accounts.google.com";
        options.ClientId = googleClientId ?? string.Empty;
        options.ClientSecret = googleClientSecret ?? string.Empty;
        options.CallbackPath = "/signin-oidc";
        options.ResponseType = "code";
        options.MapInboundClaims = false;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.SaveTokens = false;
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("email");
        options.Scope.Add("profile");
        options.TokenValidationParameters.NameClaimType = "name";
        options.Events.OnTokenValidated = context =>
        {
            var email = context.Principal?.FindFirst("email")?.Value;
            var emailVerified = context.Principal?.FindFirst("email_verified")?.Value;
            if (!string.Equals(emailVerified, "true", StringComparison.OrdinalIgnoreCase) ||
                email is null ||
                !email.EndsWith("@titansoft.com.tw", StringComparison.OrdinalIgnoreCase))
            {
                context.Fail("Sign-in requires a Google-verified @titansoft.com.tw email address.");
            }

            return Task.CompletedTask;
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddSingleton<TcpSynFingerprintStore>();
if (tcpCaptureEnabled)
    builder.Services.AddHostedService<TsharkTcpSynCaptureService>();

// HTTPS is intentionally terminated by local Kestrel so the PoC can inspect the browser ClientHello.
var certificatePath = builder.Configuration["Tls:CertificatePath"];
var privateKeyPath = builder.Configuration["Tls:PrivateKeyPath"];
X509Certificate2? serverCertificate = null;
if (!string.IsNullOrWhiteSpace(certificatePath) || !string.IsNullOrWhiteSpace(privateKeyPath))
{
    if (string.IsNullOrWhiteSpace(certificatePath) || string.IsNullOrWhiteSpace(privateKeyPath))
        throw new InvalidOperationException("Both Tls:CertificatePath and Tls:PrivateKeyPath must be configured.");

    serverCertificate = X509Certificate2.CreateFromPemFile(certificatePath, privateKeyPath);
}

if (serverCertificate is not null && !requireGoogleAuth)
    throw new InvalidOperationException("Google authentication must be enabled when Kestrel is configured with a public TLS certificate.");

builder.WebHost.ConfigureKestrel(kestrel =>
{
    if (serverCertificate is not null)
    {
        kestrel.ListenAnyIP(443, listenOptions =>
        {
            listenOptions.UseHttps(httpsOptions =>
            {
                httpsOptions.ServerCertificate = serverCertificate;
#pragma warning disable CS0618
                httpsOptions.TlsClientHelloBytesCallback = (connection, clientHello) =>
                {
                    if (TlsClientHelloFingerprint.TryCreate(clientHello.ToArray(), out var fingerprint) && fingerprint is not null)
                        tlsFingerprints[connection.ConnectionId] = fingerprint;
                };
#pragma warning restore CS0618
            });
        });
    }
    else
    {
        // Local development listeners. Production uses the explicit certificate above.
        kestrel.ListenLocalhost(5082);
        kestrel.ListenLocalhost(5081, listenOptions =>
        {
            listenOptions.UseHttps(httpsOptions =>
            {
#pragma warning disable CS0618
                httpsOptions.TlsClientHelloBytesCallback = (connection, clientHello) =>
                {
                    if (TlsClientHelloFingerprint.TryCreate(clientHello.ToArray(), out var fingerprint) && fingerprint is not null)
                        tlsFingerprints[connection.ConnectionId] = fingerprint;
                };
#pragma warning restore CS0618
            });
        });
    }
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

var featuresEndpoint = app.MapGet("/api/features", (HttpContext context, TcpSynFingerprintStore tcpFingerprints) =>
{
    context.Response.Headers.CacheControl = "no-store";
    var request = context.Request;
    var tls = context.Features.Get<ITlsHandshakeFeature>();
    var remoteIp = context.Connection.RemoteIpAddress;

    // Only collect a small allowlist. Never return cookies, authorization, or arbitrary headers.
    var headers = new Dictionary<string, string?>
    {
        ["userAgent"] = request.Headers["User-Agent"].ToString(),
        ["acceptLanguage"] = request.Headers["Accept-Language"].ToString(),
        ["acceptEncoding"] = request.Headers["Accept-Encoding"].ToString(),
        ["secChUa"] = request.Headers["Sec-CH-UA"].ToString(),
        ["secChUaPlatform"] = request.Headers["Sec-CH-UA-Platform"].ToString(),
        ["secChUaMobile"] = request.Headers["Sec-CH-UA-Mobile"].ToString(),
        ["secChUaArch"] = request.Headers["Sec-CH-UA-Arch"].ToString(),
        ["secChUaModel"] = request.Headers["Sec-CH-UA-Model"].ToString(),
        ["secChUaBitness"] = request.Headers["Sec-CH-UA-Bitness"].ToString()
    };

    return Results.Ok(new
    {
        capturedAtUtc = DateTimeOffset.UtcNow,
        request = new
        {
            request.Method,
            request.Protocol,
            request.Scheme,
            request.Host,
            request.ContentType,
            request.ContentLength,
            path = request.Path.Value,
            queryParameterCount = request.Query.Count,
            headers
        },
        connection = new
        {
            // This is the peer seen by the app. Behind a proxy it may be the proxy address.
            remoteIp = remoteIp?.ToString(),
            remoteIpIsPrivate = remoteIp is not null && IsPrivate(remoteIp),
            remotePort = context.Connection.RemotePort,
            connectionId = context.Connection.Id,
            tlsProtocol = tls?.Protocol.ToString(),
            negotiatedCipherSuite = tls?.NegotiatedCipherSuite.ToString(),
            clientHelloFingerprint = tlsFingerprints.TryGetValue(context.Connection.Id, out var fingerprint)
                ? new { ja3 = fingerprint.Ja3, ja3String = fingerprint.Ja3String, ja4 = fingerprint.Ja4, fingerprint.CipherCount, fingerprint.ExtensionCount }
                : null,
            tcpSynFingerprint = tcpFingerprints.TryGet(remoteIp, context.Connection.RemotePort, context.Connection.LocalIpAddress, context.Connection.LocalPort, out var tcpFingerprint) && tcpFingerprint is not null
                ? new
                {
                    tcpFingerprint.InitialWindow,
                    tcpFingerprint.Mss,
                    tcpFingerprint.SackPermitted,
                    tcpFingerprint.TimestampPresent,
                    tcpFingerprint.WindowScale,
                    tcpFingerprint.OptionsOrder,
                    tcpFingerprint.CapturedAtUtc
                }
                : null
        },
        serverRuntime = new
        {
            framework = RuntimeInformation.FrameworkDescription,
            os = RuntimeInformation.OSDescription,
            architecture = RuntimeInformation.ProcessArchitecture.ToString(),
            serverName = app.Environment.ApplicationName
        }
    });
});

if (requireGoogleAuth)
    featuresEndpoint.RequireAuthorization();

app.MapGet("/auth/login", () => Results.Challenge(
    new AuthenticationProperties { RedirectUri = "/api/features" },
    new[] { OpenIdConnectDefaults.AuthenticationScheme }));
app.MapGet("/auth/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/");
});
app.MapGet("/", () => Results.Content(
    "<p>Backend feature PoC</p><p><a href=\"/auth/login\">Sign in with Google</a></p>",
    "text/html; charset=utf-8"));
app.Run();

static bool IsPrivate(IPAddress address)
{
    if (address.IsIPv4MappedToIPv6)
        address = address.MapToIPv4();

    if (IPAddress.IsLoopback(address)) return true;
    var bytes = address.GetAddressBytes();
    if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        return bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 || bytes[0] == 192 && bytes[1] == 168;

    return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
           (address.IsIPv6LinkLocal || (bytes[0] & 0xfe) == 0xfc);
}
