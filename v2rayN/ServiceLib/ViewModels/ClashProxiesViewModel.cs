namespace ServiceLib.ViewModels;

public partial class ClashProxiesViewModel : MyReactiveObject
{
    private const string _tag = "ClashProxiesViewModel";
    private readonly int _delayTimeout = 99999999;
    private ClashItem _clashItem = new();
    private int _isDelayTesting;

    public ClashProxiesViewModel()
    {
        _config = AppManager.Instance.Config;

        ProxiesReloadCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await ProxiesReload();
        });
        ProxyDelayTestCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            if (!string.IsNullOrEmpty(SelectedDetail?.Name))
            {
                await TestProxyDelay(SelectedDetail.Name);
            }
        });

        GroupProxiesDelayTestCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await TestGroupProxiesDelay();
        });
        ProxiesSelectActivityCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await SetActiveProxy();
        });

        AutoRefresh = _config.ClashUIItem.ProxiesAutoRefresh;
        SortingSelected = _config.ClashUIItem.ProxiesSorting;
        RuleModeSelected = nameof(ERuleMode.Rule);

        #region WhenAnyValue && ReactiveCommand

        this.WhenAnyValue(x => x.SelectedGroup)
            .Where(y => y != null && y.Name.IsNotEmpty())
            .Subscribe(_ => RefreshProxyDetails());

        this.WhenAnyValue(x => x.RuleModeSelected)
            .Where(y => !string.IsNullOrEmpty(y))
            .Skip(1)
            .SubscribeAsync(async x => await SetRuleMode(x));

        this.WhenAnyValue(x => x.SortingSelected)
            .Where(y => y >= 0)
            .Subscribe(_ => DoSortingSelected());

        this.WhenAnyValue(x => x.AutoRefresh)
            .Where(y => y)
            .Subscribe(_ => { _config.ClashUIItem.ProxiesAutoRefresh = AutoRefresh; });

        #endregion WhenAnyValue && ReactiveCommand

        this.WhenActivated(disposables =>
        {
            var cancelDisposable = new CancellationDisposable();
            cancelDisposable.DisposeWith(disposables);
            var token = cancelDisposable.Token;

            Task.Run(() => GetClashProxiesTask(token));
        });
    }

    public BulkObservableCollection<ClashProxyModel> ProxyGroups { get; } = [];
    public BulkObservableCollection<ClashProxyModel> ProxyDetails { get; } = [];

    public BulkObservableCollection<string> ClashModes { get; } = new(Enum.GetNames<ERuleMode>().ToList());

    [Reactive] public partial ClashProxyModel? SelectedGroup { get; set; }

    [Reactive] public partial ClashProxyModel? SelectedDetail { get; set; }

    public ReactiveCommand<RxVoid, RxVoid> ProxiesReloadCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> ProxyDelayTestCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> GroupProxiesDelayTestCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> ProxiesSelectActivityCmd { get; }

    [Reactive] public partial string RuleModeSelected { get; set; }

    [Reactive] public partial int SortingSelected { get; set; }

    [Reactive] public partial bool AutoRefresh { get; set; }

    private void DoSortingSelected()
    {
        if (SortingSelected != _config.ClashUIItem.ProxiesSorting)
        {
            _config.ClashUIItem.ProxiesSorting = SortingSelected;
        }

        RefreshProxyDetails();
    }

    public async Task ProxiesReload()
    {
        try
        {
            await GetClashProxies();
            await GetClashModes();
        }
        catch (Exception ex)
        {
            //刷新失败不应影响内核重载流程
            Logging.SaveLog(_tag, ex);
            return;
        }

        //测速不阻塞重载流程（与同步上游前的行为一致），全部跑完后再回读一次，
        //把各节点的 history 带回来，切换分组时也能直接看到延迟
        if (Interlocked.CompareExchange(ref _isDelayTesting, 1, 0) != 0)
        {
            return;
        }
        _ = Task.Run(async () =>
        {
            try
            {
                await TestAllProxiesDelay();
                await GetClashProxies();
            }
            catch (Exception ex)
            {
                Logging.SaveLog(_tag, ex);
            }
            finally
            {
                Interlocked.Exchange(ref _isDelayTesting, 0);
            }
        });
    }

    #region task

    public async Task GetClashProxiesTask(CancellationToken token = default)
    {
        try
        {
            var numOfExecuted = 1;
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
            while (await timer.WaitForNextTickAsync(token).ConfigureAwait(false))
            {
                numOfExecuted++;
                if (!(AutoRefresh && AppManager.Instance.ShowInTaskbar &&
                      AppManager.Instance.IsRunningCore(ECoreType.sing_box)))
                {
                    continue;
                }

                if (_config.ClashUIItem.ProxiesRefreshInterval <= 0)
                {
                    continue;
                }

                if (numOfExecuted % _config.ClashUIItem.ProxiesRefreshInterval != 0)
                {
                    continue;
                }
                await GetClashProxies();
            }
        }
        catch (OperationCanceledException)
        {
            // Ignored
        }
        catch (Exception ex)
        {
            Logging.SaveLog("GetClashProxiesTask", ex);
        }
    }

    #endregion task

    #region proxy function

    private async Task SetRuleMode(string mode)
    {
        await ClashApiManager.Instance.UpdateClashMode(mode);
    }

    private async Task GetClashProxies()
    {
        var ret = await ClashApiManager.Instance.GetProxies();
        if (ret?.IsEmpty() != false)
        {
            return;
        }
        _clashItem = ret;

        //列表更新必须回到 UI 线程，并等待刷新完成后调用方才能继续
        var refreshed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        RxSchedulers.MainThreadScheduler.Schedule(async () =>
        {
            try
            {
                await RefreshProxyGroups();
            }
            catch (Exception ex)
            {
                Logging.SaveLog(_tag, ex);
            }
            finally
            {
                refreshed.TrySetResult();
            }
        });
        await refreshed.Task;
    }

    public async Task RefreshProxyGroups()
    {
        if (_clashItem.IsEmpty())
        {
            return;
        }

        var selectedName = SelectedGroup?.Name;

        var lstProxyGroups = new List<ClashProxyModel>();

        var globalName = "GLOBAL";
        foreach (var kv in _clashItem.Proxies)
        {
            if (!Global.allowSelectType.Contains(kv.Value.type?.ToLower()))
            {
                continue;
            }
            if (kv.Key == globalName)
            {
                continue;
            }
            var item = lstProxyGroups.FirstOrDefault(t => t.Name == kv.Key);
            if (item != null && item.Name.IsNotEmpty())
            {
                continue;
            }
            lstProxyGroups.Add(new ClashProxyModel
            {
                Now = kv.Value.now,
                Name = kv.Key,
                Type = kv.Value.type,
            });
        }
        if (_clashItem.Proxies.TryGetValue(globalName, out var globalProxy))
        {
            lstProxyGroups.Add(new ClashProxyModel
            {
                Now = globalProxy.now,
                Name = globalName,
                Type = globalProxy.type,
            });
        }

        ProxyGroups.ReplaceRange(lstProxyGroups);

        if (ProxyGroups is { Count: > 0 })
        {
            SelectedGroup = ProxyGroups.FirstOrDefault(t => t.Name == selectedName) ?? ProxyGroups.First();
        }
        else
        {
            SelectedGroup = null;
        }
        await Task.CompletedTask;
    }

    private void RefreshProxyDetails()
    {
        var name = SelectedGroup?.Name;
        if (name.IsNullOrEmpty())
        {
            return;
        }
        if (_clashItem.IsEmpty())
        {
            return;
        }

        _clashItem.Proxies.TryGetValue(name, out var proxy);
        if (proxy?.all == null)
        {
            return;
        }
        var lstDetails = new List<ClashProxyModel>();
        foreach (var item in proxy.all)
        {
            var proxy2 = TryGetProxy(item);
            if (proxy2 == null)
            {
                continue;
            }
            var delay = proxy2.history?.Count > 0 ? proxy2.history.Last().delay : -1;

            lstDetails.Add(new ClashProxyModel
            {
                IsActive = item == proxy.now,
                Name = item,
                Type = proxy2.type,
                Delay = delay <= 0 ? _delayTimeout : delay,
                DelayName = delay <= 0 ? string.Empty : $"{delay}ms",
            });
        }
        // sort
        switch (SortingSelected)
        {
            case 0:
                lstDetails = lstDetails.OrderBy(t => t.Delay).ToList();
                break;

            case 1:
                lstDetails = lstDetails.OrderBy(t => t.Name).ToList();
                break;
        }
        ProxyDetails.ReplaceRange(lstDetails);
    }

    private ClashProxy? TryGetProxy(string? name)
    {
        if (name.IsNullOrEmpty())
        {
            return null;
        }
        _clashItem.Proxies.TryGetValue(name, out var proxy2);
        return proxy2;
    }

    public async Task SetActiveProxy()
    {
        var groupName = SelectedGroup?.Name;
        var nodeName = SelectedDetail?.Name;
        if (groupName.IsNullOrEmpty() || nodeName.IsNullOrEmpty())
        {
            return;
        }
        var selectedProxy = TryGetProxy(groupName);
        if (selectedProxy is not { type: "Selector" })
        {
            NoticeManager.Instance.Enqueue(ResUI.OperationFailed);
            return;
        }

        await ClashApiManager.Instance.SetActiveProxy(groupName, nodeName);
        await GetClashProxies();
        NoticeManager.Instance.Enqueue(ResUI.OperationSuccess);
    }

    private async Task GetClashModes()
    {
        var ret = await ClashApiManager.Instance.GetClashModes();
        if (ret is not { Count: > 0 })
        {
            return;
        }
        ClashModes.ReplaceRange(ret);
        var currentMode = await ClashApiManager.Instance.GetClashMode();
        if (currentMode.IsNullOrEmpty())
        {
            return;
        }
        RuleModeSelected = currentMode;
    }

    private async Task TestProxyDelay(string name)
    {
        var result = await ClashApiManager.Instance.TestDelay(name, _clashItem);
        var model = new SpeedTestResult
        {
            IndexId = name,
            Delay = result.ToString(),
        };
        RxSchedulers.MainThreadScheduler.Schedule(() => _ = ProxiesDelayTestResult(model));
        await Task.CompletedTask;
    }

    /// <summary>
    /// 测速当前选中分组下的全部节点（闪电按钮）
    /// </summary>
    private async Task TestGroupProxiesDelay()
    {
        var groupProxy = TryGetProxy(SelectedGroup?.Name);
        //接口返回的分组类型是 "Selector"/"URLTest"/"Fallback"，必须忽略大小写后再比较
        if (!Global.allowSelectType.Contains(groupProxy?.type?.ToLower()))
        {
            return;
        }

        var members = groupProxy?.all;
        if (members == null)
        {
            return;
        }

        //跳过嵌套的分组，只测真实节点
        var names = members
            .Where(name => name.IsNotEmpty()
                           && !Global.notAllowTestType.Contains(TryGetProxy(name)?.type?.ToLower()))
            .ToList();

        await TestProxiesDelay(names);
    }

    /// <summary>
    /// 测速所有真实节点（不含分组），用于刷新/内核启动后自动填充延迟
    /// </summary>
    private async Task TestAllProxiesDelay()
    {
        var names = _clashItem.Proxies
            .Where(kv => kv.Key.IsNotEmpty()
                         && !Global.notAllowTestType.Contains(kv.Value.type?.ToLower()))
            .Select(kv => kv.Key)
            .ToList();

        await TestProxiesDelay(names);
    }

    private async Task TestProxiesDelay(IEnumerable<string> names)
    {
        var options = new ParallelOptions
        {
            MaxDegreeOfParallelism = 8,
        };
        await Parallel.ForEachAsync(names, options, async (name, _) =>
        {
            await TestProxyDelay(name);
        });
    }

    public async Task ProxiesDelayTestResult(SpeedTestResult result)
    {
        var detail = ProxyDetails.FirstOrDefault(it => it.Name == result.IndexId);
        if (detail == null)
        {
            return;
        }

        //测速失败时保持空白，不要显示成 -1ms（与同步上游前一致）
        if (int.TryParse(result.Delay, out var delay) && delay > 0)
        {
            detail.Delay = delay;
            detail.DelayName = $"{delay}ms";
        }
        else
        {
            detail.Delay = _delayTimeout;
            detail.DelayName = string.Empty;
        }
        await Task.CompletedTask;
    }

    #endregion proxy function
}
