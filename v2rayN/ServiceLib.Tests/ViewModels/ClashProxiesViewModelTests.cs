using ReactiveUI.Builder;
using ServiceLib.Tests.CoreConfig;
using ServiceLib.ViewModels;

namespace ServiceLib.Tests.ViewModels;

[NotInParallel]
public class ClashProxiesViewModelTests
{
    static ClashProxiesViewModelTests()
    {
        RxAppBuilder.CreateReactiveUIBuilder().WithCoreServices().BuildApp();
    }

    [Test]
    public async Task ProxiesReload_ShouldTestRealProxiesAndRefreshDelayHistory()
    {
        var configField = typeof(AppManager).GetField("_config", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var portField = typeof(AppManager).GetField("_statePort2", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var viewConfigField = typeof(MyReactiveObject).GetField("_config", BindingFlags.Static | BindingFlags.NonPublic)!;
        var previousConfig = configField.GetValue(AppManager.Instance);
        var previousPort = portField.GetValue(AppManager.Instance);
        var previousViewConfig = viewConfigField.GetValue(null);
        var proxyReads = 0;
        var delayTests = 0;
        var delayTestsAtProxyReads = new ConcurrentQueue<int>();

        const string proxiesWithoutHistory = """
            {"proxies":{"GLOBAL":{"type":"Selector","all":["test-group"],"now":"test-group"},"test-group":{"type":"Selector","all":["test-node","nested-group"],"now":"test-node"},"test-node":{"type":"Shadowsocks","history":[]},"nested-group":{"type":"Selector","all":["nested-node"],"now":"nested-node"},"nested-node":{"type":"Shadowsocks","history":[]}}}
            """;
        const string proxiesWithHistory = """
            {"proxies":{"GLOBAL":{"type":"Selector","all":["test-group"],"now":"test-group"},"test-group":{"type":"Selector","all":["test-node","nested-group"],"now":"test-node"},"test-node":{"type":"Shadowsocks","history":[{"delay":42}]},"nested-group":{"type":"Selector","all":["nested-node"],"now":"nested-node"},"nested-node":{"type":"Shadowsocks","history":[{"delay":42}]}}}
            """;

        await using var server = new DelayServer(request =>
        {
            var path = request.Split(' ', StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(1);
            if (path == "/proxies")
            {
                Interlocked.Increment(ref proxyReads);
                var testedCount = Volatile.Read(ref delayTests);
                delayTestsAtProxyReads.Enqueue(testedCount);
                return testedCount > 0 ? proxiesWithHistory : proxiesWithoutHistory;
            }
            if (path is "/providers/proxies" or "/configs")
            {
                return "{}";
            }
            if (path is not null
                && path.StartsWith("/proxies/", StringComparison.Ordinal)
                && path.Contains("/delay?", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref delayTests);
                return "{\"delay\":42}";
            }
            return "{}";
        });

        try
        {
            CoreConfigTestFactory.BindAppManagerConfig(CoreConfigTestFactory.CreateConfig());
            portField.SetValue(AppManager.Instance, server.Port);
            var viewModel = new ClashProxiesViewModel();
            var delayTestingField = typeof(ClashProxiesViewModel).GetField("_isDelayTesting", BindingFlags.Instance | BindingFlags.NonPublic)!;

            await viewModel.ProxiesReload().WaitAsync(TimeSpan.FromSeconds(10));
            await WaitForConditionAsync(
                () => Volatile.Read(ref proxyReads) >= 2
                      && Volatile.Read(ref delayTests) == 2
                      && (int)delayTestingField.GetValue(viewModel)! == 0,
                TimeSpan.FromSeconds(10));

            await delayTests.Should().BeEqualTo(2);
            await delayTestsAtProxyReads.Last().Should().BeEqualTo(2);
            await viewModel.ProxyDetails.Single(item => item.Name == "test-node").DelayName.Should().BeEqualTo("42ms");
            await server.Requests.Count(request => request.Contains("/proxies/test-node/delay?", StringComparison.Ordinal))
                .Should().BeEqualTo(1);
            await server.Requests.Any(request => request.Contains("/proxies/nested-group/delay?", StringComparison.Ordinal))
                .Should().BeFalse();
        }
        finally
        {
            configField.SetValue(AppManager.Instance, previousConfig);
            portField.SetValue(AppManager.Instance, previousPort);
            viewConfigField.SetValue(null, previousViewConfig);
        }
    }

    [Test]
    public async Task ProxyDelayTestResult_ShouldShowMinusOneForFailedDelay()
    {
        var configField = typeof(AppManager).GetField("_config", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var viewConfigField = typeof(MyReactiveObject).GetField("_config", BindingFlags.Static | BindingFlags.NonPublic)!;
        var previousConfig = configField.GetValue(AppManager.Instance);
        var previousViewConfig = viewConfigField.GetValue(null);
        try
        {
            CoreConfigTestFactory.BindAppManagerConfig(CoreConfigTestFactory.CreateConfig());
            var viewModel = new ClashProxiesViewModel();
            viewModel.ProxyDetails.Add(new ClashProxyModel { Name = "failed-node" });

            await viewModel.ProxiesDelayTestResult(new SpeedTestResult
            {
                IndexId = "failed-node",
                Delay = "-1",
            });

            await viewModel.ProxyDetails.Single().DelayName.Should().BeEqualTo("-1");
        }
        finally
        {
            configField.SetValue(AppManager.Instance, previousConfig);
            viewConfigField.SetValue(null, previousViewConfig);
        }
    }

    [Test]
    [Arguments("Selector", true)]
    [Arguments("URLTest", true)]
    [Arguments("LoadBalance", true)]
    [Arguments("Fallback", true)]
    [Arguments("selector", true)]
    [Arguments("SELECTOR", true)]
    [Arguments("Direct", false)]
    [Arguments(null, false)]
    public async Task GroupDelay_ShouldTestAllowedGroupTypes(string? type, bool allowed)
    {
        var configField = typeof(AppManager).GetField("_config", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var portField = typeof(AppManager).GetField("_statePort2", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var viewConfigField = typeof(MyReactiveObject).GetField("_config", BindingFlags.Static | BindingFlags.NonPublic)!;
        var previousConfig = configField.GetValue(AppManager.Instance);
        var previousPort = portField.GetValue(AppManager.Instance);
        var previousViewConfig = viewConfigField.GetValue(null);
        await using var server = new DelayServer();
        try
        {
            CoreConfigTestFactory.BindAppManagerConfig(CoreConfigTestFactory.CreateConfig());
            portField.SetValue(AppManager.Instance, server.Port);
            var viewModel = new ClashProxiesViewModel();
            var item = new ClashItem();
            item.Proxies.Add("test-group", new() { type = type, all = ["test-node"] });
            item.Proxies.Add("test-node", new() { type = "Shadowsocks" });
            typeof(ClashProxiesViewModel).GetField("_clashItem", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(viewModel, item);
            viewModel.SelectedGroup = new ClashProxyModel { Name = "test-group" };

            var method = typeof(ClashProxiesViewModel).GetMethod("TestGroupProxiesDelay", BindingFlags.Instance | BindingFlags.NonPublic)!;
            await ((Task)method.Invoke(viewModel, null)!).WaitAsync(TimeSpan.FromSeconds(10));

            await server.Requests.Count.Should().BeEqualTo(allowed ? 1 : 0);
            await viewModel.ProxyDetails.Single().DelayName.Should().BeEqualTo(allowed ? "42ms" : string.Empty);
            if (allowed)
            {
                await server.Requests.Single().StartsWith("GET /proxies/test-node/delay?").Should().BeTrue();
            }
        }
        finally
        {
            configField.SetValue(AppManager.Instance, previousConfig);
            portField.SetValue(AppManager.Instance, previousPort);
            viewConfigField.SetValue(null, previousViewConfig);
        }
    }

    private static async Task WaitForConditionAsync(Func<bool> condition, TimeSpan timeout)
    {
        var stopwatch = Stopwatch.StartNew();
        while (!condition())
        {
            if (stopwatch.Elapsed >= timeout)
            {
                throw new TimeoutException("The expected proxy delay history was not refreshed.");
            }
            await Task.Delay(20);
        }
    }

    private sealed class DelayServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _cancellation = new();
        private readonly Func<string, string>? _responseFactory;
        private readonly Task _serverTask;
        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
        public ConcurrentQueue<string> Requests { get; } = new();

        public DelayServer(Func<string, string>? responseFactory = null)
        {
            _responseFactory = responseFactory;
            _listener.Start();
            _serverTask = ServeAsync();
        }

        private async Task ServeAsync()
        {
            var token = _cancellation.Token;
            while (!token.IsCancellationRequested)
            {
                using var client = await _listener.AcceptTcpClientAsync(token);
                await using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                var request = await reader.ReadLineAsync(token);
                while (await reader.ReadLineAsync(token) is { Length: > 0 })
                {
                }
                Requests.Enqueue(request!);
                var body = _responseFactory?.Invoke(request!) ?? "{\"delay\":42}";
                var response = $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(response), token);
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _cancellation.CancelAsync();
            _listener.Stop();
            try
            {
                await _serverTask;
            }
            catch (OperationCanceledException)
            {
            }
            finally
            {
                _cancellation.Dispose();
            }
        }
    }
}
