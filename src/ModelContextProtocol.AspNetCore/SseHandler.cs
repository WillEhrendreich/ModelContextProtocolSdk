using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Server;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace ModelContextProtocol.AspNetCore;

internal sealed partial class SseHandler(
    IOptions<McpServerOptions> mcpServerOptionsSnapshot,
    IOptionsFactory<McpServerOptions> mcpServerOptionsFactory,
    IOptions<HttpServerTransportOptions> httpMcpServerOptions,
    IHostApplicationLifetime hostApplicationLifetime,
    ILoggerFactory loggerFactory)
{
    private readonly ConcurrentDictionary<string, SseSession> _sessions = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider = httpMcpServerOptions.Value.TimeProvider;
    private readonly ILogger _logger = loggerFactory.CreateLogger<SseHandler>();

    public int SessionCount => _sessions.Count;

    public async Task HandleSseRequestAsync(HttpContext context)
    {
        // Circuit breaker: reject new SSE connections when over the limit.
        // This prevents reconnect storms from overwhelming the server — rejected connections
        // return 503 immediately without allocating session resources.
        var maxSessions = httpMcpServerOptions.Value.MaxIdleSessionCount;
        if (_sessions.Count >= maxSessions)
        {
            // Trigger a prune cycle inline to free up space
            PruneIdleSessions();

            // If still over limit after pruning, reject
            if (_sessions.Count >= maxSessions)
            {
                LogSseConnectionRejected(_sessions.Count, maxSessions);
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                context.Response.Headers["Retry-After"] = "5";
                await context.Response.WriteAsync("Too many SSE sessions. Retry later.");
                return;
            }
        }

        var sessionId = StreamableHttpHandler.MakeNewSessionId();

        // If the server is shutting down, we need to cancel all SSE connections immediately without waiting for HostOptions.ShutdownTimeout
        // which defaults to 30 seconds.
        using var sseCts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, hostApplicationLifetime.ApplicationStopping);
        var cancellationToken = sseCts.Token;

        StreamableHttpHandler.InitializeSseResponse(context);

        var requestPath = (context.Request.PathBase + context.Request.Path).ToString();
        var endpointPattern = requestPath[..(requestPath.LastIndexOf('/') + 1)];
        await using var transport = new SseResponseStreamTransport(context.Response.Body, $"{endpointPattern}message?sessionId={sessionId}", sessionId);

        var userIdClaim = StreamableHttpHandler.GetUserIdClaim(context.User);
        var sseSession = new SseSession(transport, userIdClaim, sseCts, context, _timeProvider.GetTimestamp());

        if (!_sessions.TryAdd(sessionId, sseSession))
        {
            throw new UnreachableException($"Unreachable given good entropy! Session with ID '{sessionId}' has already been created.");
        }

        try
        {
            var mcpServerOptions = mcpServerOptionsSnapshot.Value;
            if (httpMcpServerOptions.Value.ConfigureSessionOptions is { } configureSessionOptions)
            {
                mcpServerOptions = mcpServerOptionsFactory.Create(Options.DefaultName);
                await configureSessionOptions(context, mcpServerOptions, cancellationToken);
            }

            var transportTask = transport.RunAsync(cancellationToken);

            try
            {
                await using var mcpServer = McpServer.Create(transport, mcpServerOptions, loggerFactory, context.RequestServices);
                context.Features.Set(mcpServer);

                var runSessionAsync = httpMcpServerOptions.Value.RunSessionHandler ?? StreamableHttpHandler.RunSessionAsync;
                await runSessionAsync(context, mcpServer, cancellationToken);
            }
            finally
            {
                await transport.DisposeAsync();
                await transportTask;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // RequestAborted always triggers when the client disconnects before a complete response body is written,
            // but this is how SSE connections are typically closed.
        }
        finally
        {
            _sessions.TryRemove(sessionId, out _);
        }
    }

    public async Task HandleMessageRequestAsync(HttpContext context)
    {
        if (!context.Request.Query.TryGetValue("sessionId", out var sessionId))
        {
            await Results.BadRequest("Missing sessionId query parameter.").ExecuteAsync(context);
            return;
        }

        if (!_sessions.TryGetValue(sessionId.ToString(), out var sseSession))
        {
            await Results.BadRequest($"Session ID not found.").ExecuteAsync(context);
            return;
        }

        if (sseSession.UserId != StreamableHttpHandler.GetUserIdClaim(context.User))
        {
            await Results.Forbid().ExecuteAsync(context);
            return;
        }

        // Update activity timestamp — this session is actively being used
        sseSession.LastActivityTicks = _timeProvider.GetTimestamp();

        var message = await StreamableHttpHandler.ReadJsonRpcMessageAsync(context);
        if (message is null)
        {
            await Results.BadRequest("No message in request body.").ExecuteAsync(context);
            return;
        }

        await sseSession.Transport.OnMessageReceivedAsync(message, context.RequestAborted);
        context.Response.StatusCode = StatusCodes.Status202Accepted;
        await context.Response.WriteAsync("Accepted");
    }

    /// <summary>
    /// Prunes SSE sessions that have been idle longer than <see cref="HttpServerTransportOptions.IdleTimeout"/>,
    /// and enforces <see cref="HttpServerTransportOptions.MaxIdleSessionCount"/> by cancelling the oldest idle sessions.
    /// Called by <see cref="IdleTrackingBackgroundService"/> on the same 5-second interval used for Streamable HTTP sessions.
    /// </summary>
    public void PruneIdleSessions()
    {
        var options = httpMcpServerOptions.Value;
        var idleTimeout = options.IdleTimeout;
        var maxIdleSessionCount = options.MaxIdleSessionCount;

        if (idleTimeout == Timeout.InfiniteTimeSpan && maxIdleSessionCount >= int.MaxValue)
        {
            return;
        }

        var now = _timeProvider.GetTimestamp();
        var idleTimeoutTicks = idleTimeout == Timeout.InfiniteTimeSpan
            ? long.MaxValue
            : (long)(idleTimeout.Ticks * _timeProvider.TimestampFrequency / (double)TimeSpan.TicksPerSecond);
        var cutoff = now - idleTimeoutTicks;

        // First pass: remove sessions that exceed IdleTimeout
        List<(string Id, long Ticks)>? remaining = null;
        foreach (var (id, session) in _sessions)
        {
            if (session.Cts.IsCancellationRequested)
            {
                continue;
            }

            if (session.LastActivityTicks < cutoff)
            {
                LogSseIdleSessionTimeout(id, idleTimeout);
                CancelAndRemoveSession(id);
                continue;
            }

            remaining ??= [];
            remaining.Add((id, session.LastActivityTicks));
        }

        // Second pass: enforce MaxIdleSessionCount by removing oldest
        if (remaining is not null && remaining.Count > maxIdleSessionCount)
        {
            remaining.Sort((a, b) => a.Ticks.CompareTo(b.Ticks));
            var toRemove = remaining.Count - maxIdleSessionCount;
            for (var i = 0; i < toRemove; i++)
            {
                LogSseIdleSessionLimit(remaining[i].Id, maxIdleSessionCount);
                CancelAndRemoveSession(remaining[i].Id);
            }
        }
    }

    /// <summary>
    /// Cancels and removes all SSE sessions, typically called during graceful shutdown.
    /// </summary>
    public void CancelAllSessions()
    {
        foreach (var (id, _) in _sessions)
        {
            CancelAndRemoveSession(id);
        }
    }

    private void CancelAndRemoveSession(string sessionId)
    {
        if (_sessions.TryRemove(sessionId, out var session))
        {
            try
            {
                // Abort the HTTP connection immediately — sends TCP RST, no graceful FIN handshake.
                // This is necessary because CTS cancellation alone doesn't close the TCP socket fast
                // enough to combat reconnect storms (~200+ connections/sec from misbehaving clients).
                session.HttpContext.Abort();
                session.Cts.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // CTS already disposed by the HandleSseRequestAsync finally block — session is already cleaning up
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "SSE IdleTimeout of {IdleTimeout} exceeded. Closing idle SSE session {SessionId}.")]
    private partial void LogSseIdleSessionTimeout(string sessionId, TimeSpan idleTimeout);

    [LoggerMessage(Level = LogLevel.Information, Message = "SSE MaxIdleSessionCount of {MaxIdleSessionCount} exceeded. Closing idle SSE session {SessionId}.")]
    private partial void LogSseIdleSessionLimit(string sessionId, int maxIdleSessionCount);

    [LoggerMessage(Level = LogLevel.Warning, Message = "SSE connection rejected: {SessionCount} active sessions >= MaxIdleSessionCount {MaxIdleSessionCount}.")]
    private partial void LogSseConnectionRejected(int sessionCount, int maxIdleSessionCount);

    private sealed class SseSession(SseResponseStreamTransport transport, UserIdClaim? userId, CancellationTokenSource cts, HttpContext httpContext, long createdTicks)
    {
        public SseResponseStreamTransport Transport { get; } = transport;
        public UserIdClaim? UserId { get; } = userId;
        public CancellationTokenSource Cts { get; } = cts;
        public HttpContext HttpContext { get; } = httpContext;
        public long LastActivityTicks { get; set; } = createdTicks;
    }
}
