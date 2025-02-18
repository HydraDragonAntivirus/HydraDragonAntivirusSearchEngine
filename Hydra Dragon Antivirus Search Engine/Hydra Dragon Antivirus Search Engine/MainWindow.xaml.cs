using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using System.Windows;
using Microsoft.Win32;
using IOPath = System.IO.Path;
using log4net;
using log4net.Config;

namespace Hydra_Dragon_Antivirus_Search_Engine
{
    public partial class MainWindow : Window
    {
        // Scanner instance.
        private Scanner? scanner;

        // Cancellation token for scan cancellation.
        private CancellationTokenSource cts = new();

        // Flag to track scan state.
        private bool isScanning = false;

        // Lists for different file categories.
        private readonly List<string> malwareFilesIPv4 = new();
        private readonly List<string> malwareFilesIPv6 = new();
        private readonly List<string> DDoSFilesIPv4 = new();
        private readonly List<string> DDoSFilesIPv6 = new();
        private readonly List<string> phishingFilesIPv4 = new();
        private readonly List<string> phishingFilesIPv6 = new();
        private readonly List<string> WhiteListFilesIPv4 = new();
        private readonly List<string> WhiteListFilesIPv6 = new();

        // Folder paths.
        private string malwarePath = string.Empty;
        private string ddosPath = string.Empty;
        private string phishingPath = string.Empty;
        private string whiteListPath = string.Empty;
        // CSV folder paths.
        private string realTimeBulkPath = string.Empty;
        private string realTimeCsvWhiteListPath = string.Empty;

        // Logging helpers.
        private readonly ConcurrentQueue<string> logQueue = new();
        private readonly List<string> fullLogList = new();
        private System.Timers.Timer? logFlushTimer;

        // JSON options.
        private static readonly JsonSerializerOptions jsonOptions = new() { WriteIndented = true };

        // Real-time CSV StreamWriters.
        private StreamWriter? realtimeBulkWriter;
        private StreamWriter? realtimeWhiteListWriter;

        public MainWindow()
        {
            InitializeComponent();
            XmlConfigurator.Configure();
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            if (cts != null && !cts.IsCancellationRequested)
            {
                cts.Cancel();
            }
            StopLogFlusher();
            realtimeBulkWriter?.Close();
            realtimeWhiteListWriter?.Close();
            base.OnClosing(e);
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            StartLogFlusher();
            // Set default UI values.
            textBoxMaxDepth.Text = "10";
            textBoxMaxThreads.Text = "100";
            textBoxCsvMaxLines.Text = "10000";
            textBoxCsvMaxSize.Text = "2097152";
            textBoxOutputFile.Text = "BulkReport.csv";
            textBoxWhiteListOutputFile.Text = "WhiteListReport.csv";
            textBoxCategoryMalicious.Text = "20";
            textBoxCategoryPhishing.Text = "7";
            textBoxCategoryDDoS.Text = "18";
            textBoxCommentTemplate.Text = "Related with ip address detected by heuristics of https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine (Source IP: {ip}, Source URL: {source_url}, Discovered URL: {discovered_url}, Verdict: {verdict}, Depth: {depth})";
        }

        #region UI Helper Methods and Event Handlers

        private void StartLogFlusher()
        {
            logFlushTimer = new System.Timers.Timer(300);
            logFlushTimer.Elapsed += (s, e) =>
            {
                if (!listBoxLog.Dispatcher.HasShutdownStarted)
                {
                    List<string> logsToFlush = new();
                    while (logQueue.TryDequeue(out string? log))
                    {
                        logsToFlush.Add(log);
                    }
                    if (logsToFlush.Count > 0)
                    {
                        listBoxLog.Dispatcher.BeginInvoke(new Action(() =>
                        {
                            foreach (var log in logsToFlush)
                                listBoxLog.Items.Add(log);
                        }));
                    }
                }
            };
            logFlushTimer.Start();
        }

        private void StopLogFlusher()
        {
            if (logFlushTimer != null)
            {
                logFlushTimer.Stop();
                logFlushTimer.Dispose();
            }
        }

        private async Task SaveSettingsAsync(string filePath)
        {
            AppSettings settings = new()
            {
                MaxDepth = int.TryParse(textBoxMaxDepth.Text, out int depth) ? depth : 10,
                MaxThreads = int.TryParse(textBoxMaxThreads.Text, out int threads) ? threads : 100,
                CsvMaxLines = int.TryParse(textBoxCsvMaxLines.Text, out int lines) ? lines : 10000,
                CsvMaxSize = int.TryParse(textBoxCsvMaxSize.Text, out int size) ? size : 2097152,
                OutputFile = textBoxOutputFile.Text,
                WhiteListOutputFile = textBoxWhiteListOutputFile.Text,
                CategoryMalicious = textBoxCategoryMalicious.Text,
                CategoryPhishing = textBoxCategoryPhishing.Text,
                CategoryDDoS = textBoxCategoryDDoS.Text,
                CommentTemplate = textBoxCommentTemplate.Text,
                RealTimeCsvBulk = checkBoxRealTimeCsvBulk.IsChecked.GetValueOrDefault(),
                RealTimeCsvBulkFile = textBoxRealTimeCsvBulkFile.Text,
                RealTimeCsvWhiteList = checkBoxRealTimeCsvWhiteList.IsChecked.GetValueOrDefault(),
                RealTimeCsvWhiteListFile = textBoxRealTimeCsvWhiteListFile.Text,
                RealTimeSave = checkBoxRealTimeSave.IsChecked.GetValueOrDefault(),
                RealTimeFile = textBoxRealTimeFile.Text,
                ScanKnownActive = checkBoxScanKnownActive.IsChecked.GetValueOrDefault(),
                MalwareFilesIPv4 = malwareFilesIPv4,
                MalwareFilesIPv6 = malwareFilesIPv6,
                DDoSFilesIPv4 = DDoSFilesIPv4,
                DDoSFilesIPv6 = DDoSFilesIPv6,
                PhishingFilesIPv4 = phishingFilesIPv4,
                PhishingFilesIPv6 = phishingFilesIPv6,
                WhiteListFilesIPv4 = WhiteListFilesIPv4,
                WhiteListFilesIPv6 = WhiteListFilesIPv6,
                MalwarePath = malwarePath,
                DDoSPath = ddosPath,
                PhishingPath = phishingPath,
                WhiteListPath = whiteListPath,
                RealTimeCsvBulkPath = realTimeBulkPath,
                RealTimeCsvWhiteListPath = realTimeCsvWhiteListPath
            };

            string json = JsonSerializer.Serialize(settings, jsonOptions);
            await File.WriteAllTextAsync(filePath, json);
        }

        private async Task LoadSettingsAsync(string filePath)
        {
            if (File.Exists(filePath))
            {
                string json = await File.ReadAllTextAsync(filePath);
                AppSettings? settings = JsonSerializer.Deserialize<AppSettings>(json);
                if (settings != null)
                {
                    settings.OutputFile = ConvertToAbsolutePath(settings.OutputFile);
                    settings.WhiteListOutputFile = ConvertToAbsolutePath(settings.WhiteListOutputFile);
                    settings.RealTimeCsvBulkFile = ConvertToAbsolutePath(settings.RealTimeCsvBulkFile);
                    settings.RealTimeCsvWhiteListFile = ConvertToAbsolutePath(settings.RealTimeCsvWhiteListFile);
                    settings.RealTimeFile = ConvertToAbsolutePath(settings.RealTimeFile);
                    settings.MalwarePath = ConvertToAbsolutePath(settings.MalwarePath);
                    settings.DDoSPath = ConvertToAbsolutePath(settings.DDoSPath);
                    settings.PhishingPath = ConvertToAbsolutePath(settings.PhishingPath);
                    settings.WhiteListPath = ConvertToAbsolutePath(settings.WhiteListPath);

                    textBoxMaxDepth.Text = settings.MaxDepth.ToString();
                    textBoxMaxThreads.Text = settings.MaxThreads.ToString();
                    textBoxCsvMaxLines.Text = settings.CsvMaxLines.ToString();
                    textBoxCsvMaxSize.Text = settings.CsvMaxSize.ToString();
                    textBoxOutputFile.Text = settings.OutputFile;
                    textBoxWhiteListOutputFile.Text = settings.WhiteListOutputFile;
                    textBoxCategoryMalicious.Text = settings.CategoryMalicious;
                    textBoxCategoryPhishing.Text = settings.CategoryPhishing;
                    textBoxCategoryDDoS.Text = settings.CategoryDDoS;
                    textBoxCommentTemplate.Text = settings.CommentTemplate;

                    checkBoxRealTimeCsvBulk.IsChecked = settings.RealTimeCsvBulk;
                    textBoxRealTimeCsvBulkFile.Text = settings.RealTimeCsvBulkFile;
                    checkBoxRealTimeCsvWhiteList.IsChecked = settings.RealTimeCsvWhiteList;
                    textBoxRealTimeCsvWhiteListFile.Text = settings.RealTimeCsvWhiteListFile;
                    checkBoxRealTimeSave.IsChecked = settings.RealTimeSave;
                    textBoxRealTimeFile.Text = settings.RealTimeFile;
                    checkBoxScanKnownActive.IsChecked = settings.ScanKnownActive;

                    malwareFilesIPv4.Clear();
                    foreach (var file in settings.MalwareFilesIPv4)
                        malwareFilesIPv4.Add(ConvertToAbsolutePath(file));
                    malwareFilesIPv6.Clear();
                    foreach (var file in settings.MalwareFilesIPv6)
                        malwareFilesIPv6.Add(ConvertToAbsolutePath(file));
                    DDoSFilesIPv4.Clear();
                    foreach (var file in settings.DDoSFilesIPv4)
                        DDoSFilesIPv4.Add(ConvertToAbsolutePath(file));
                    DDoSFilesIPv6.Clear();
                    foreach (var file in settings.DDoSFilesIPv6)
                        DDoSFilesIPv6.Add(ConvertToAbsolutePath(file));
                    phishingFilesIPv4.Clear();
                    foreach (var file in settings.PhishingFilesIPv4)
                        phishingFilesIPv4.Add(ConvertToAbsolutePath(file));
                    phishingFilesIPv6.Clear();
                    foreach (var file in settings.PhishingFilesIPv6)
                        phishingFilesIPv6.Add(ConvertToAbsolutePath(file));
                    WhiteListFilesIPv4.Clear();
                    foreach (var file in settings.WhiteListFilesIPv4)
                        WhiteListFilesIPv4.Add(ConvertToAbsolutePath(file));
                    WhiteListFilesIPv6.Clear();
                    foreach (var file in settings.WhiteListFilesIPv6)
                        WhiteListFilesIPv6.Add(ConvertToAbsolutePath(file));

                    listBoxMalwareIPv4.Items.Clear();
                    foreach (var item in malwareFilesIPv4)
                        listBoxMalwareIPv4.Items.Add(item);
                    listBoxMalwareIPv6.Items.Clear();
                    foreach (var item in malwareFilesIPv6)
                        listBoxMalwareIPv6.Items.Add(item);

                    listBoxDDoSIPv4.Items.Clear();
                    foreach (var item in DDoSFilesIPv4)
                        listBoxDDoSIPv4.Items.Add(item);
                    listBoxDDoSIPv6.Items.Clear();
                    foreach (var item in DDoSFilesIPv6)
                        listBoxDDoSIPv6.Items.Add(item);

                    listBoxPhishingIPv4.Items.Clear();
                    foreach (var item in phishingFilesIPv4)
                        listBoxPhishingIPv4.Items.Add(item);
                    listBoxPhishingIPv6.Items.Clear();
                    foreach (var item in phishingFilesIPv6)
                        listBoxPhishingIPv6.Items.Add(item);

                    listBoxWhiteListIPv4.Items.Clear();
                    foreach (var item in WhiteListFilesIPv4)
                        listBoxWhiteListIPv4.Items.Add(item);
                    listBoxWhiteListIPv6.Items.Clear();
                    foreach (var item in WhiteListFilesIPv6)
                        listBoxWhiteListIPv6.Items.Add(item);

                    malwarePath = settings.MalwarePath;
                    ddosPath = settings.DDoSPath;
                    phishingPath = settings.PhishingPath;
                    whiteListPath = settings.WhiteListPath;
                    realTimeBulkPath = string.IsNullOrEmpty(settings.RealTimeCsvBulkPath)
                        ? (IOPath.GetDirectoryName(settings.RealTimeCsvBulkFile) ?? Environment.CurrentDirectory)
                        : settings.RealTimeCsvBulkPath;
                    realTimeCsvWhiteListPath = string.IsNullOrEmpty(settings.RealTimeCsvWhiteListPath)
                        ? (IOPath.GetDirectoryName(settings.RealTimeCsvWhiteListFile) ?? Environment.CurrentDirectory)
                        : settings.RealTimeCsvWhiteListPath;
                }
            }
        }

        private static string ConvertToAbsolutePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return path;
            if (IOPath.IsPathRooted(path))
                return IOPath.GetFullPath(path);
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            return IOPath.GetFullPath(IOPath.Combine(baseDir, path));
        }

        private void BtnBrowseRealTimeLog_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new()
            {
                Filter = "Text Files|*.txt|All Files|*.*",
                Title = "Select Real-Time Log File"
            };
            if (sfd.ShowDialog() == true)
                textBoxRealTimeFile.Text = sfd.FileName;
        }

        private void BtnBrowseOutputFile_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new()
            {
                Filter = "CSV Files|*.csv|All Files|*.*",
                Title = "Select Output File"
            };
            if (sfd.ShowDialog() == true)
                textBoxOutputFile.Text = sfd.FileName;
        }

        private void BtnBrowseWhiteListOutputFile_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new()
            {
                Filter = "CSV Files|*.csv|All Files|*.*",
                Title = "Select WhiteList Output File"
            };
            if (sfd.ShowDialog() == true)
                textBoxWhiteListOutputFile.Text = sfd.FileName;
        }

        private void BtnBrowseBulkCsv_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new()
            {
                Filter = "CSV Files|*.csv|All Files|*.*",
                Title = "Select Real-Time Bulk CSV File"
            };
            if (sfd.ShowDialog() == true)
                textBoxRealTimeCsvBulkFile.Text = sfd.FileName;
        }

        private void BtnBrowseWhiteListCsv_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new()
            {
                Filter = "CSV Files|*.csv|All Files|*.*",
                Title = "Select Real-Time WhiteList CSV File"
            };
            if (sfd.ShowDialog() == true)
                textBoxRealTimeCsvWhiteListFile.Text = sfd.FileName;
        }

        private async void BtnSaveSettings_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new() { Filter = "JSON Files|*.json" };
            if (sfd.ShowDialog() == true)
            {
                await SaveSettingsAsync(sfd.FileName);
                MessageBox.Show("Settings saved successfully.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private async void BtnLoadSettings_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new() { Filter = "JSON Files|*.json" };
            bool? result = ofd.ShowDialog();
            if (result == true)
            {
                await LoadSettingsAsync(ofd.FileName);
                MessageBox.Show("Settings loaded successfully.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        // Open StreamWriters for real-time CSV writing with header.
        private async Task InitializeRealtimeCsvFilesAsync()
        {
            if (checkBoxRealTimeCsvBulk.IsChecked == true && !string.IsNullOrEmpty(textBoxRealTimeCsvBulkFile.Text))
            {
                string bulkDirectory = IOPath.GetDirectoryName(textBoxRealTimeCsvBulkFile.Text) ?? Environment.CurrentDirectory;
                if (!Directory.Exists(bulkDirectory))
                    Directory.CreateDirectory(bulkDirectory);
                realtimeBulkWriter = new StreamWriter(textBoxRealTimeCsvBulkFile.Text, false, Encoding.UTF8) { AutoFlush = true };
                realtimeBulkWriter.WriteLine("IP,Categories,ReportDate,Comment");
            }
            if (checkBoxRealTimeCsvWhiteList.IsChecked == true && !string.IsNullOrEmpty(textBoxRealTimeCsvWhiteListFile.Text))
            {
                string whiteListDirectory = IOPath.GetDirectoryName(textBoxRealTimeCsvWhiteListFile.Text) ?? Environment.CurrentDirectory;
                if (!Directory.Exists(whiteListDirectory))
                    Directory.CreateDirectory(whiteListDirectory);
                realtimeWhiteListWriter = new StreamWriter(textBoxRealTimeCsvWhiteListFile.Text, false, Encoding.UTF8) { AutoFlush = true };
                realtimeWhiteListWriter.WriteLine("IP,Categories,ReportDate,Comment");
            }
            await Task.CompletedTask;
        }

        private async Task AppendBulkCsvLineToFileAsync(string line)
        {
            if (realtimeBulkWriter != null)
            {
                realtimeBulkWriter.WriteLine(line);
                await realtimeBulkWriter.FlushAsync();
            }
        }

        private async Task AppendWhiteListCsvLineToFileAsync(string line)
        {
            if (realtimeWhiteListWriter != null)
            {
                realtimeWhiteListWriter.WriteLine(line);
                await realtimeWhiteListWriter.FlushAsync();
            }
        }

        private async void UpdateLog(string message)
        {
            string logEntry = $"{DateTime.Now}: {message}";
            fullLogList.Add(logEntry);
            logQueue.Enqueue(logEntry);

            bool isRealTimeSaveEnabled = false;
            string realTimeFilePath = "";
            try
            {
                if (!listBoxLog.Dispatcher.HasShutdownStarted)
                {
                    await listBoxLog.Dispatcher.InvokeAsync(() =>
                    {
                        isRealTimeSaveEnabled = checkBoxRealTimeSave.IsChecked == true;
                        realTimeFilePath = textBoxRealTimeFile.Text;
                    });
                }
            }
            catch { }

            if (isRealTimeSaveEnabled && !string.IsNullOrEmpty(realTimeFilePath))
            {
                const int maxRetries = 3;
                int attempt = 0;
                bool success = false;
                while (attempt < maxRetries && !success)
                {
                    try
                    {
                        await File.AppendAllTextAsync(realTimeFilePath, logEntry + Environment.NewLine);
                        success = true;
                    }
                    catch (TaskCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        attempt++;
                        if (attempt >= maxRetries)
                        {
                            try
                            {
                                if (!listBoxLog.Dispatcher.HasShutdownStarted)
                                    await listBoxLog.Dispatcher.InvokeAsync(() => logQueue.Enqueue("Error saving realtime log: " + ex.Message));
                            }
                            catch { }
                        }
                        else
                        {
                            await Task.Delay(100);
                        }
                    }
                }
            }
        }

        private async void UpdateProgress(int current, int total)
        {
            await progressBarScan.Dispatcher.InvokeAsync(() =>
            {
                progressBarScan.Maximum = total;
                progressBarScan.Value = current;
                textBlockProgress.Text = $"{current} / {total}";
            });
        }

        // BtnStartScan_Click event handler.
        private async void BtnStartScan_Click(object sender, RoutedEventArgs e)
        {
            if (!isScanning)
            {
                isScanning = true;
                BtnStartScan.Content = "Stop Scan";
                try
                {
                    int maxDepth = int.TryParse(textBoxMaxDepth.Text, out int d) ? d : 10;
                    int maxThreads = int.TryParse(textBoxMaxThreads.Text, out int t) ? t : 100;
                    int csvMaxLines = int.TryParse(textBoxCsvMaxLines.Text, out int cl) ? cl : 10000;
                    int csvMaxSize = int.TryParse(textBoxCsvMaxSize.Text, out int cs) ? cs : 2097152;
                    string outputFileName = textBoxOutputFile.Text;
                    string whiteListOutputFileName = textBoxWhiteListOutputFile.Text;
                    string categoryMalicious = textBoxCategoryMalicious.Text;
                    string categoryPhishing = textBoxCategoryPhishing.Text;
                    string categoryDDoS = textBoxCategoryDDoS.Text;
                    string commentTemplate = textBoxCommentTemplate.Text;
                    // Use scanKnownActiveHarmful for harmful seeds.
                    bool scanKnownActiveHarmful = checkBoxScanKnownActive.IsChecked.GetValueOrDefault();
                    bool allowAutoVerdict = checkBoxAllowAutoVerdict.IsChecked.GetValueOrDefault();

                    // Initialize real-time CSV files.
                    await InitializeRealtimeCsvFilesAsync();
                    cts = new CancellationTokenSource();

                    // Start scanner for IPv4.
                    scanner = new Scanner(
                        malwareFilesIPv4,
                        DDoSFilesIPv4,
                        phishingFilesIPv4,
                        WhiteListFilesIPv4,
                        maxDepth,
                        maxThreads,
                        categoryMalicious,
                        categoryPhishing,
                        categoryDDoS,
                        csvMaxLines,
                        csvMaxSize,
                        outputFileName,
                        whiteListOutputFileName,
                        UpdateLog,
                        UpdateProgress,
                        AppendBulkCsvLineToFileAsync,
                        AppendWhiteListCsvLineToFileAsync,
                        commentTemplate,
                        UpdateCurrentFileMessage,
                        scanKnownActiveHarmful,
                        allowAutoVerdict,
                        "ipv4"
                    );
                    await scanner.StartScanAsync(cts.Token);

                    // Start scanner for IPv6.
                    scanner = new Scanner(
                        malwareFilesIPv6,
                        DDoSFilesIPv6,
                        phishingFilesIPv6,
                        WhiteListFilesIPv6,
                        maxDepth,
                        maxThreads,
                        categoryMalicious,
                        categoryPhishing,
                        categoryDDoS,
                        csvMaxLines,
                        csvMaxSize,
                        outputFileName,
                        whiteListOutputFileName,
                        UpdateLog,
                        UpdateProgress,
                        AppendBulkCsvLineToFileAsync,
                        AppendWhiteListCsvLineToFileAsync,
                        commentTemplate,
                        UpdateCurrentFileMessage,
                        scanKnownActiveHarmful,
                        allowAutoVerdict,
                        "ipv6"
                    );
                    await scanner.StartScanAsync(cts.Token);

                    bool csvOk = await scanner.FinalizeCsvFilesAsync();
                    if (!csvOk)
                        MessageBox.Show("CSV output exceeds the defined limits.", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                    else
                        MessageBox.Show("Scan completed and CSV files generated successfully.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (OperationCanceledException)
                {
                    UpdateLog("Scan cancelled by the user.");
                }
                catch (Exception ex)
                {
                    UpdateLog("Error: " + ex.Message);
                }
                finally
                {
                    isScanning = false;
                    BtnStartScan.Content = "Start Scan";
                }
            }
            else
            {
                if (cts != null && !cts.IsCancellationRequested)
                {
                    cts.Cancel();
                    UpdateLog("Scan cancellation requested.");
                }
            }
        }

        private void UpdateCurrentFileMessage(string message)
        {
            if (textBlockCurrentFile.Dispatcher.CheckAccess())
                textBlockCurrentFile.Text = message;
            else
                textBlockCurrentFile.Dispatcher.Invoke(() => textBlockCurrentFile.Text = message);
        }

        #endregion

        #region List Handlers for Seed Files

        private void BtnBrowseMalwareIPv4_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new()
            {
                Filter = "Text Files|*.txt",
                InitialDirectory = string.IsNullOrEmpty(malwarePath) ? Environment.CurrentDirectory : malwarePath
            };
            if (ofd.ShowDialog() == true)
            {
                string filePath = ofd.FileName;
                malwarePath = IOPath.GetDirectoryName(filePath) ?? Environment.CurrentDirectory;
                malwareFilesIPv4.Add(filePath);
                listBoxMalwareIPv4.Items.Add(filePath);
            }
        }

        private void BtnAddMalwareIPv4_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBoxMalwareIPv4Input.Text))
            {
                if (textBoxMalwareIPv4Input.Text.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    listBoxMalwareIPv4.Items.Add(textBoxMalwareIPv4Input.Text);
                    malwareFilesIPv4.Add(textBoxMalwareIPv4Input.Text);
                    textBoxMalwareIPv4Input.Clear();
                }
                else
                    MessageBox.Show("The file is not a txt file.");
            }
            else
                MessageBox.Show("The file does not exist.");
        }

        private void BtnDeleteMalwareIPv4_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxMalwareIPv4.SelectedIndex >= 0)
            {
                int index = listBoxMalwareIPv4.SelectedIndex;
                malwareFilesIPv4.RemoveAt(index);
                listBoxMalwareIPv4.Items.RemoveAt(index);
            }
        }

        private void BtnBrowseMalwareIPv6_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new()
            {
                Filter = "Text Files|*.txt",
                InitialDirectory = string.IsNullOrEmpty(malwarePath) ? Environment.CurrentDirectory : malwarePath
            };
            if (ofd.ShowDialog() == true)
            {
                string filePath = ofd.FileName;
                malwarePath = IOPath.GetDirectoryName(filePath) ?? Environment.CurrentDirectory;
                malwareFilesIPv6.Add(filePath);
                listBoxMalwareIPv6.Items.Add(filePath);
            }
        }

        private void BtnAddMalwareIPv6_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBoxMalwareIPv6Input.Text))
            {
                if (textBoxMalwareIPv6Input.Text.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    listBoxMalwareIPv6.Items.Add(textBoxMalwareIPv6Input.Text);
                    malwareFilesIPv6.Add(textBoxMalwareIPv6Input.Text);
                    textBoxMalwareIPv6Input.Clear();
                }
                else
                    MessageBox.Show("The file is not a txt file.");
            }
            else
                MessageBox.Show("The file does not exist.");
        }

        private void BtnDeleteMalwareIPv6_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxMalwareIPv6.SelectedIndex >= 0)
            {
                int index = listBoxMalwareIPv6.SelectedIndex;
                malwareFilesIPv6.RemoveAt(index);
                listBoxMalwareIPv6.Items.RemoveAt(index);
            }
        }

        private void BtnBrowseDDoSIPv4_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new()
            {
                Filter = "Text Files|*.txt",
                InitialDirectory = string.IsNullOrEmpty(ddosPath) ? Environment.CurrentDirectory : ddosPath
            };
            if (ofd.ShowDialog() == true)
            {
                string filePath = ofd.FileName;
                ddosPath = IOPath.GetDirectoryName(filePath) ?? Environment.CurrentDirectory;
                DDoSFilesIPv4.Add(filePath);
                listBoxDDoSIPv4.Items.Add(filePath);
            }
        }

        private void BtnAddDDoSIPv4_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBoxDDoSIPv4Input.Text))
            {
                if (textBoxDDoSIPv4Input.Text.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    listBoxDDoSIPv4.Items.Add(textBoxDDoSIPv4Input.Text);
                    DDoSFilesIPv4.Add(textBoxDDoSIPv4Input.Text);
                    textBoxDDoSIPv4Input.Clear();
                }
                else
                    MessageBox.Show("The file is not a txt file.");
            }
            else
                MessageBox.Show("The file does not exist.");
        }

        private void BtnDeleteDDoSIPv4_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxDDoSIPv4.SelectedIndex >= 0)
            {
                int index = listBoxDDoSIPv4.SelectedIndex;
                DDoSFilesIPv4.RemoveAt(index);
                listBoxDDoSIPv4.Items.RemoveAt(index);
            }
        }

        private void BtnBrowseDDoSIPv6_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new()
            {
                Filter = "Text Files|*.txt",
                InitialDirectory = string.IsNullOrEmpty(ddosPath) ? Environment.CurrentDirectory : ddosPath
            };
            if (ofd.ShowDialog() == true)
            {
                string filePath = ofd.FileName;
                ddosPath = IOPath.GetDirectoryName(filePath) ?? Environment.CurrentDirectory;
                DDoSFilesIPv6.Add(filePath);
                listBoxDDoSIPv6.Items.Add(filePath);
            }
        }

        private void BtnAddDDoSIPv6_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBoxDDoSIPv6Input.Text))
            {
                if (textBoxDDoSIPv6Input.Text.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    listBoxDDoSIPv6.Items.Add(textBoxDDoSIPv6Input.Text);
                    DDoSFilesIPv6.Add(textBoxDDoSIPv6Input.Text);
                    textBoxDDoSIPv6Input.Clear();
                }
                else
                    MessageBox.Show("The file is not a txt file.");
            }
            else
                MessageBox.Show("The file does not exist.");
        }

        private void BtnDeleteDDoSIPv6_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxDDoSIPv6.SelectedIndex >= 0)
            {
                int index = listBoxDDoSIPv6.SelectedIndex;
                DDoSFilesIPv6.RemoveAt(index);
                listBoxDDoSIPv6.Items.RemoveAt(index);
            }
        }

        private void BtnBrowsePhishingIPv4_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new()
            {
                Filter = "Text Files|*.txt",
                InitialDirectory = string.IsNullOrEmpty(phishingPath) ? Environment.CurrentDirectory : phishingPath
            };
            if (ofd.ShowDialog() == true)
            {
                string filePath = ofd.FileName;
                phishingPath = IOPath.GetDirectoryName(filePath) ?? Environment.CurrentDirectory;
                phishingFilesIPv4.Add(filePath);
                listBoxPhishingIPv4.Items.Add(filePath);
            }
        }

        private void BtnAddPhishingIPv4_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBoxPhishingIPv4Input.Text))
            {
                if (textBoxPhishingIPv4Input.Text.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    listBoxPhishingIPv4.Items.Add(textBoxPhishingIPv4Input.Text);
                    phishingFilesIPv4.Add(textBoxPhishingIPv4Input.Text);
                    textBoxPhishingIPv4Input.Clear();
                }
                else
                    MessageBox.Show("The file is not a txt file.");
            }
            else
                MessageBox.Show("The file does not exist.");
        }

        private void BtnDeletePhishingIPv4_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxPhishingIPv4.SelectedIndex >= 0)
            {
                int index = listBoxPhishingIPv4.SelectedIndex;
                phishingFilesIPv4.RemoveAt(index);
                listBoxPhishingIPv4.Items.RemoveAt(index);
            }
        }

        private void BtnBrowsePhishingIPv6_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new()
            {
                Filter = "Text Files|*.txt",
                InitialDirectory = string.IsNullOrEmpty(phishingPath) ? Environment.CurrentDirectory : phishingPath
            };
            if (ofd.ShowDialog() == true)
            {
                string filePath = ofd.FileName;
                phishingPath = IOPath.GetDirectoryName(filePath) ?? Environment.CurrentDirectory;
                phishingFilesIPv6.Add(filePath);
                listBoxPhishingIPv6.Items.Add(filePath);
            }
        }

        private void BtnAddPhishingIPv6_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBoxPhishingIPv6Input.Text))
            {
                if (textBoxPhishingIPv6Input.Text.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    listBoxPhishingIPv6.Items.Add(textBoxPhishingIPv6Input.Text);
                    phishingFilesIPv6.Add(textBoxPhishingIPv6Input.Text);
                    textBoxPhishingIPv6Input.Clear();
                }
                else
                    MessageBox.Show("The file is not a txt file.");
            }
            else
                MessageBox.Show("The file does not exist.");
        }

        private void BtnDeletePhishingIPv6_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxPhishingIPv6.SelectedIndex >= 0)
            {
                int index = listBoxPhishingIPv6.SelectedIndex;
                phishingFilesIPv6.RemoveAt(index);
                listBoxPhishingIPv6.Items.RemoveAt(index);
            }
        }

        private void BtnBrowseWhiteListIPv4_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new()
            {
                Filter = "Text Files|*.txt",
                InitialDirectory = string.IsNullOrEmpty(whiteListPath) ? Environment.CurrentDirectory : whiteListPath
            };
            if (ofd.ShowDialog() == true)
            {
                string filePath = ofd.FileName;
                whiteListPath = IOPath.GetDirectoryName(filePath) ?? Environment.CurrentDirectory;
                WhiteListFilesIPv4.Add(filePath);
                listBoxWhiteListIPv4.Items.Add(filePath);
            }
        }

        private void BtnAddWhiteListIPv4_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBoxWhiteListIPv4Input.Text))
            {
                if (textBoxWhiteListIPv4Input.Text.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    listBoxWhiteListIPv4.Items.Add(textBoxWhiteListIPv4Input.Text);
                    WhiteListFilesIPv4.Add(textBoxWhiteListIPv4Input.Text);
                    textBoxWhiteListIPv4Input.Clear();
                }
                else
                    MessageBox.Show("The file is not a txt file.");
            }
            else
                MessageBox.Show("The file does not exist.");
        }

        private void BtnDeleteWhiteListIPv4_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxWhiteListIPv4.SelectedIndex >= 0)
            {
                int index = listBoxWhiteListIPv4.SelectedIndex;
                WhiteListFilesIPv4.RemoveAt(index);
                listBoxWhiteListIPv4.Items.RemoveAt(index);
            }
        }

        private void BtnBrowseWhiteListIPv6_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new()
            {
                Filter = "Text Files|*.txt",
                InitialDirectory = string.IsNullOrEmpty(whiteListPath) ? Environment.CurrentDirectory : whiteListPath
            };
            if (ofd.ShowDialog() == true)
            {
                string filePath = ofd.FileName;
                whiteListPath = IOPath.GetDirectoryName(filePath) ?? Environment.CurrentDirectory;
                WhiteListFilesIPv6.Add(filePath);
                listBoxWhiteListIPv6.Items.Add(filePath);
            }
        }

        private void BtnAddWhiteListIPv6_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBoxWhiteListIPv6Input.Text))
            {
                if (textBoxWhiteListIPv6Input.Text.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    listBoxWhiteListIPv6.Items.Add(textBoxWhiteListIPv6Input.Text);
                    WhiteListFilesIPv6.Add(textBoxWhiteListIPv6Input.Text);
                    textBoxWhiteListIPv6Input.Clear();
                }
                else
                    MessageBox.Show("The file is not a txt file.");
            }
            else
                MessageBox.Show("The file does not exist.");
        }

        private void BtnDeleteWhiteListIPv6_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxWhiteListIPv6.SelectedIndex >= 0)
            {
                int index = listBoxWhiteListIPv6.SelectedIndex;
                WhiteListFilesIPv6.RemoveAt(index);
                listBoxWhiteListIPv6.Items.RemoveAt(index);
            }
        }

        // Log clear and save handlers.
        private void BtnClearLog_Click(object sender, RoutedEventArgs e)
        {
            listBoxLog.Items.Clear();
            fullLogList.Clear();
        }

        private void BtnSaveLog_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new()
            {
                Filter = "Text Files|*.txt|All Files|*.*",
                Title = "Save Log File"
            };
            if (sfd.ShowDialog() == true)
            {
                File.WriteAllLines(sfd.FileName, fullLogList);
                MessageBox.Show("Log saved successfully.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        #endregion

        #region Scanner and Helper Classes

        public class AppSettings
        {
            public int MaxDepth { get; set; }
            public int MaxThreads { get; set; }
            public int CsvMaxLines { get; set; }
            public int CsvMaxSize { get; set; }
            public string OutputFile { get; set; } = string.Empty;
            public string WhiteListOutputFile { get; set; } = string.Empty;
            public string CategoryMalicious { get; set; } = string.Empty;
            public string CategoryPhishing { get; set; } = string.Empty;
            public string CategoryDDoS { get; set; } = string.Empty;
            public string CommentTemplate { get; set; } = string.Empty;
            public bool RealTimeCsvBulk { get; set; }
            public string RealTimeCsvBulkFile { get; set; } = string.Empty;
            public bool RealTimeCsvWhiteList { get; set; }
            public string RealTimeCsvWhiteListFile { get; set; } = string.Empty;
            public bool RealTimeSave { get; set; }
            public string RealTimeFile { get; set; } = string.Empty;
            public bool ScanKnownActive { get; set; }
            public List<string> MalwareFilesIPv4 { get; set; } = new();
            public List<string> MalwareFilesIPv6 { get; set; } = new();
            public List<string> DDoSFilesIPv4 { get; set; } = new();
            public List<string> DDoSFilesIPv6 { get; set; } = new();
            public List<string> PhishingFilesIPv4 { get; set; } = new();
            public List<string> PhishingFilesIPv6 { get; set; } = new();
            public List<string> WhiteListFilesIPv4 { get; set; } = new();
            public List<string> WhiteListFilesIPv6 { get; set; } = new();
            public string MalwarePath { get; set; } = string.Empty;
            public string DDoSPath { get; set; } = string.Empty;
            public string PhishingPath { get; set; } = string.Empty;
            public string WhiteListPath { get; set; } = string.Empty;
            public string RealTimeCsvBulkPath { get; set; } = string.Empty;
            public string RealTimeCsvWhiteListPath { get; set; } = string.Empty;
        }

        public partial class Scanner
        {
            // Logger for Scanner.
            private readonly ILog scannerLogger = LogManager.GetLogger(typeof(Scanner));

            public string SelectedIPType { get; set; }
            private readonly List<string> malwareFiles;
            private readonly List<string> DDoSFiles;
            private readonly List<string> phishingFiles;
            private readonly List<string> WhiteListFiles;
            private readonly int maxDepth;
            private readonly int maxThreads;
            private readonly string categoryMalicious;
            private readonly string categoryPhishing;
            private readonly string categoryDDoS;
            private readonly int csvMaxLines;
            private readonly int csvMaxSize;
            private readonly string outputFileName;
            private readonly string WhiteListOutputFileName;
            private readonly string commentTemplate;
            private readonly Action<string> logCallback;
            private readonly Action<int, int> progressCallback;
            private readonly Func<string, Task> realTimeBulkCsvCallback;
            private readonly Func<string, Task> realTimeWhiteListCsvCallback;
            private readonly Action<string> scanProgressCallback;
            public List<string> BulkCsvLines { get; private set; } = new();
            public List<string> WhiteListCsvLines { get; private set; } = new();
            private readonly ConcurrentQueue<Seed> seedQueue = new();
            private readonly ConcurrentDictionary<string, bool> processedIPs = new();
            int totalSeeds = 0;
            int processedCount = 0;
            private readonly HttpClient httpClient = new();
            // scanKnownActiveHarmful applies only to harmful seeds.
            private readonly bool scanKnownActiveHarmful;
            private readonly bool allowAutoVerdict;
            private readonly object bulkCsvLock = new();

            public Scanner(
                List<string> malwareFiles,
                List<string> DDoSFiles,
                List<string> phishingFiles,
                List<string> WhiteListFiles,
                int maxDepth,
                int maxThreads,
                string categoryMalicious,
                string categoryPhishing,
                string categoryDDoS,
                int csvMaxLines,
                int csvMaxSize,
                string outputFileName,
                string WhiteListOutputFileName,
                Action<string> logCallback,
                Action<int, int> progressCallback,
                Func<string, Task> realTimeBulkCsvCallback,
                Func<string, Task> realTimeWhiteListCsvCallback,
                string commentTemplate,
                Action<string> scanProgressCallback,
                bool scanKnownActiveHarmful = false,
                bool allowAutoVerdict = true,
                string selectedIPType = "ipv4")
            {
                this.malwareFiles = malwareFiles;
                this.DDoSFiles = DDoSFiles;
                this.phishingFiles = phishingFiles;
                this.WhiteListFiles = WhiteListFiles;
                this.maxDepth = maxDepth;
                this.maxThreads = maxThreads;
                this.categoryMalicious = categoryMalicious;
                this.categoryPhishing = categoryPhishing;
                this.categoryDDoS = categoryDDoS;
                this.csvMaxLines = csvMaxLines;
                this.csvMaxSize = csvMaxSize;
                this.outputFileName = outputFileName;
                this.WhiteListOutputFileName = WhiteListOutputFileName;
                this.logCallback = logCallback;
                this.progressCallback = progressCallback;
                this.realTimeBulkCsvCallback = realTimeBulkCsvCallback;
                this.realTimeWhiteListCsvCallback = realTimeWhiteListCsvCallback;
                this.commentTemplate = string.IsNullOrEmpty(commentTemplate)
                    ? "Related with ip address detected by heuristics of https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine (Source IP: {ip}, Source URL: {source_url}, Discovered URL: {discovered_url}, Verdict: {verdict}, Depth: {depth})"
                    : commentTemplate;
                this.scanProgressCallback = scanProgressCallback;
                this.scanKnownActiveHarmful = scanKnownActiveHarmful;
                this.allowAutoVerdict = allowAutoVerdict;
                this.SelectedIPType = selectedIPType;
            }

            public async Task<bool> FinalizeCsvFilesAsync()
            {
                // Ensure the header exists in the bulk CSV.
                string header = "IP,Categories,ReportDate,Comment";
                if (BulkCsvLines.Count == 0 || !BulkCsvLines[0].StartsWith(header))
                {
                    BulkCsvLines.Insert(0, header);
                }

                int totalLines = BulkCsvLines.Count;
                string csvContent = string.Join("\n", BulkCsvLines);
                int csvSizeInBytes = Encoding.UTF8.GetByteCount(csvContent);

                if (totalLines > csvMaxLines + 1)
                {
                    logCallback($"CSV output exceeds the maximum allowed number of lines ({csvMaxLines}).");
                    return false;
                }
                else if (csvSizeInBytes > csvMaxSize)
                {
                    logCallback($"CSV output exceeds the maximum allowed file size ({csvMaxSize} bytes).");
                    return false;
                }
                else
                {
                    await File.WriteAllLinesAsync(outputFileName, BulkCsvLines, Encoding.UTF8);
                    await File.WriteAllLinesAsync(WhiteListOutputFileName, WhiteListCsvLines, Encoding.UTF8);
                    logCallback("CSV files generated successfully.");
                    return true;
                }
            }

            public async Task StartScanAsync(CancellationToken token)
            {
                try
                {
                    // Priority: WhiteList, then Phishing, then DDoS, then Malicious.
                    await LoadSeedsFromFileListAsync(WhiteListFiles, "WhiteList", token);
                    await LoadSeedsFromFileListAsync(phishingFiles, "phishing", token);
                    await LoadSeedsFromFileListAsync(DDoSFiles, "DDoS", token);
                    await LoadSeedsFromFileListAsync(malwareFiles, "malicious", token);
                    totalSeeds = seedQueue.Count;
                    progressCallback(processedCount, totalSeeds);
                    List<Task> workers = new();
                    for (int i = 0; i < maxThreads; i++)
                    {
                        workers.Add(Task.Run(() => WorkerAsync(token), token));
                    }
                    await Task.WhenAll(workers);
                    logCallback("Scanning completed. Processed " + processedCount + " seeds.");
                }
                catch (OperationCanceledException)
                {
                    logCallback("Scan canceled by the user.");
                }
            }

            private async Task LoadSeedsFromFileListAsync(List<string> fileList, string defaultSourceType, CancellationToken token)
            {
                foreach (var file in fileList.Where(file => Path.GetExtension(file).Equals(".txt", StringComparison.OrdinalIgnoreCase)))
                {
                    if (token.IsCancellationRequested)
                        return;
                    scanProgressCallback($"Current Loaded Definition File: {file}");
                    logCallback($"Loading file: {file}");
                    string[] lines = await File.ReadAllLinesAsync(file, token);
                    foreach (var line in lines)
                    {
                        if (token.IsCancellationRequested)
                            break;
                        string trimmed = line.Trim();
                        if (string.IsNullOrEmpty(trimmed))
                            continue;
                        string ip = trimmed;
                        int? port = null;
                        if (SelectedIPType.Equals("ipv4", StringComparison.OrdinalIgnoreCase))
                        {
                            var parts = trimmed.Split(':');
                            if (parts.Length > 1 && int.TryParse(parts[1], out int parsedPort))
                            {
                                ip = parts[0];
                                port = parsedPort;
                            }
                        }
                        seedQueue.Enqueue(new Seed(ip, defaultSourceType, SelectedIPType.ToLower(), port, 1, trimmed, trimmed));
                    }
                    logCallback($"Finished loading file: {file}");
                }
            }

            private async Task WorkerAsync(CancellationToken token)
            {
                while (!token.IsCancellationRequested)
                {
                    if (seedQueue.TryDequeue(out Seed? seed) && seed is not null)
                    {
                        await ProcessSeedAsync(seed, token);
                        processedCount++;
                        progressCallback(processedCount, totalSeeds);
                        await Task.Yield();
                    }
                    else
                    {
                        break;
                    }
                }
            }

            public async Task ProcessSeedAsync(Seed seed, CancellationToken token)
            {
                if (seed.Depth > maxDepth)
                    return;

                string url = seed.GetUrl();
                scannerLogger.Info($"Processing (Depth {seed.Depth}): {url}");
                logCallback($"Processing (Depth {seed.Depth}): {url}");
                try
                {
                    var response = await httpClient.GetAsync(url, token);
                    if (!response.IsSuccessStatusCode)
                    {
                        scannerLogger.Warn($"Failed: {url} Status: {response.StatusCode}");
                        logCallback($"Failed: {url} Status: {response.StatusCode}");
                        return;
                    }

                    string content = await response.Content.ReadAsStringAsync(token);
                    if (string.IsNullOrEmpty(content))
                        return;

                    scannerLogger.Info($"Visited (Depth {seed.Depth}): {url}");
                    logCallback($"Visited (Depth {seed.Depth}): {url}");

                    string category = seed.SourceType switch
                    {
                        "malicious" => categoryMalicious,
                        "phishing" => categoryPhishing,
                        "DDoS" => categoryDDoS,
                        _ => ""
                    };

                    string reportDate = DateTime.UtcNow.ToString("o");
                    string comment = commentTemplate
                        .Replace("{ip}", seed.IP)
                        .Replace("{source_url}", seed.OriginalSourceUrl)
                        .Replace("{discovered_url}", seed.DiscoveredUrl)
                        .Replace("{verdict}", seed.SourceType)
                        .Replace("{depth}", seed.Depth.ToString());

                    if (comment.Length > 1024)
                        comment = comment[..1024];

                    // Only add bulk CSV entry for harmful seeds (non-WhiteList) when at depth > 0 or when scanKnownActiveHarmful is true.
                    if (!seed.SourceType.Equals("WhiteList", StringComparison.OrdinalIgnoreCase) &&
                        (scanKnownActiveHarmful || seed.Depth > 0))
                    {
                        string csvLine = $"{seed.IP},\"{category}\",{reportDate},\"{EscapeCsvField(comment)}\"";
                        lock (bulkCsvLock)
                        {
                            BulkCsvLines.Add(csvLine);
                        }
                        await realTimeBulkCsvCallback(csvLine);
                    }

                    if (seed.Depth < maxDepth)
                    {
                        EnqueueSeed(new Seed(seed.IP, seed.SourceType, seed.Version, seed.Port, seed.Depth + 1, seed.OriginalSourceUrl, seed.DiscoveredUrl));
                    }

                    var tasks = new List<Task>();

                    string ipv4Pattern = @"\b(?<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::(?<port>[0-9]{1,5}))?\b";
                    foreach (Match m in Regex.Matches(content, ipv4Pattern))
                    {
                        tasks.Add(ProcessMatch(m, "ipv4", url, m.Value, seed.SourceType, seed.Depth + 1, token));
                    }

                    string ipv6Pattern = @"\b(?<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})(?::(?<port>[0-9]{1,5}))?\b";
                    foreach (Match m in Regex.Matches(content, ipv6Pattern))
                    {
                        tasks.Add(ProcessMatch(m, "ipv6", url, m.Value, seed.SourceType, seed.Depth + 1, token));
                    }

                    await Task.WhenAll(tasks);
                }
                catch (Exception ex)
                {
                    scannerLogger.Error($"Error processing {url}: {ex.Message}");
                    logCallback($"Error processing {url}: {ex.Message}");
                }
            }

            private async Task ProcessMatch(Match match, string version, string file, string trimmed, string defaultSourceType, int currentDepth, CancellationToken token)
            {
                string ip = match.Groups["ip"].Value;
                int? port = match.Groups["port"].Success ? (int?)int.Parse(match.Groups["port"].Value) : null;

                if (!processedIPs.TryAdd(ip, true))
                    return;

                await ProcessIPAsync(new Seed(ip, defaultSourceType, version, port, currentDepth, file, trimmed), ip, port, version, trimmed, token);
            }

            private static string ConvertToUrl(string? url, string? baseUrl = "")
            {
                if (string.IsNullOrWhiteSpace(url))
                    return string.Empty;

                if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    return url;
                }

                if (url.StartsWith("//"))
                {
                    return "http:" + url;
                }

                if (!string.IsNullOrEmpty(baseUrl) && Uri.TryCreate(baseUrl, UriKind.Absolute, out Uri? baseUri))
                {
                    if (Uri.TryCreate(baseUri, url, out Uri? combinedUri))
                    {
                        return combinedUri.ToString();
                    }
                }

                return "http://" + url;
            }

            [GeneratedRegex(@"href\s*=\s*[""'](?<url>[^""']+)[""']", RegexOptions.IgnoreCase)]
            private static partial Regex HrefRegex();

            private static List<string> ExtractURLsFromHtml(string? htmlContent, string? baseUrl = "")
            {
                var urls = new List<string>();

                if (string.IsNullOrEmpty(htmlContent))
                    return urls;

                var regex = HrefRegex();
                var matches = regex.Matches(htmlContent);

                foreach (Match match in matches)
                {
                    string? extractedUrl = match.Groups["url"].Value.Trim();

                    if (string.IsNullOrEmpty(extractedUrl))
                        continue;

                    extractedUrl = ConvertToUrl(extractedUrl, baseUrl);

                    if (Uri.TryCreate(extractedUrl, UriKind.Absolute, out Uri? validatedUri))
                    {
                        urls.Add(validatedUri.ToString());
                    }
                }

                return urls;
            }

            private async Task ProcessIPAsync(Seed seed, string ip, int? port, string version, string discoveredUrl, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();

                discoveredUrl = ConvertToUrl(discoveredUrl, seed.OriginalSourceUrl);

                // Skip if discovered URL is empty or identical to the source.
                if (string.IsNullOrWhiteSpace(discoveredUrl) || discoveredUrl == seed.OriginalSourceUrl)
                {
                    logCallback($"Skipping discovered URL '{discoveredUrl}' as it is empty or identical to the source.");
                    return;
                }

                if (processedIPs.ContainsKey(discoveredUrl))
                    return;

                string newSourceType = seed.SourceType;

                scannerLogger.Info($"Processing URL: {discoveredUrl} (IP: {ip}) at Depth: {seed.Depth} from Source URL: {seed.OriginalSourceUrl}");
                logCallback($"Processing URL: {discoveredUrl} (IP: {ip}) at Depth: {seed.Depth} from Source URL: {seed.OriginalSourceUrl}");

                if (newSourceType.Equals("WhiteList", StringComparison.OrdinalIgnoreCase) && discoveredUrl == seed.OriginalSourceUrl)
                {
                    scannerLogger.Info($"Skipping {discoveredUrl} - Already Whitelisted.");
                    logCallback($"Skipping {discoveredUrl} - Already Whitelisted.");
                    return;
                }

                if (allowAutoVerdict)
                {
                    bool active = await SeedHelper.IsActiveAndStaticAsync(ip, port ?? 0, token);
                    // Set auto-verdict type and build the whitelist comment.
                    newSourceType = active ? "benign (auto verdict 2)" : "benign (auto verdict 3)";
                    string whitelistComment = commentTemplate
                        .Replace("{ip}", ip)
                        .Replace("{source_url}", seed.OriginalSourceUrl)
                        .Replace("{discovered_url}", discoveredUrl)
                        .Replace("{verdict}", "WhiteList")
                        .Replace("{depth}", seed.Depth.ToString());
                    string csvLine = $"{ip},\"WhiteList\",{DateTime.UtcNow:O},\"{EscapeCsvField(whitelistComment)}\"";
                    lock (WhiteListCsvLines)
                    {
                        if (WhiteListCsvLines.Count < csvMaxLines + 1)
                            WhiteListCsvLines.Add(csvLine);
                    }
                    await realTimeWhiteListCsvCallback(csvLine);
                    return;
                }

                // For harmful seeds (non-WhiteList) add bulk CSV entry.
                if (!newSourceType.Equals("WhiteList", StringComparison.OrdinalIgnoreCase))
                {
                    // Compute the comment for harmful seeds.
                    string comment = commentTemplate
                        .Replace("{ip}", seed.IP)
                        .Replace("{source_url}", seed.OriginalSourceUrl)
                        .Replace("{discovered_url}", discoveredUrl)
                        .Replace("{verdict}", newSourceType)
                        .Replace("{depth}", seed.Depth.ToString());
                    string csvLine = $"{discoveredUrl},\"{newSourceType}\",{DateTime.UtcNow:O},\"{EscapeCsvField(comment)}\"";
                    lock (bulkCsvLock)
                    {
                        BulkCsvLines.Add(csvLine);
                    }
                    await realTimeBulkCsvCallback(csvLine);
                }

                try
                {
                    var content = await DownloadHtmlContentAsync(discoveredUrl, token);
                    var newURLs = ExtractURLsFromHtml(content, discoveredUrl);

                    foreach (var newUrl in newURLs)
                    {
                        if (newUrl == seed.OriginalSourceUrl)
                        {
                            logCallback($"Skipping discovered URL '{newUrl}' as it is identical to the source.");
                            continue;
                        }
                        EnqueueSeed(new Seed(ip, "unknown", version, port ?? 0, seed.Depth + 1, seed.OriginalSourceUrl, newUrl));
                    }
                }
                catch (Exception ex)
                {
                    scannerLogger.Error($"Error fetching content from {discoveredUrl}: {ex.Message}");
                    logCallback($"Error fetching content from {discoveredUrl}: {ex.Message}");
                }

                string ipAddress = GetIpFromUrl(discoveredUrl);
                if (!string.IsNullOrEmpty(ipAddress) && !processedIPs.ContainsKey(ipAddress))
                {
                    string whitelistComment = commentTemplate
                        .Replace("{ip}", ip)
                        .Replace("{source_url}", seed.OriginalSourceUrl)
                        .Replace("{discovered_url}", discoveredUrl)
                        .Replace("{verdict}", "WhiteList")
                        .Replace("{depth}", seed.Depth.ToString());
                    string csvLine = $"{ipAddress},\"WhiteList\",{DateTime.UtcNow:O},\"{EscapeCsvField(whitelistComment)}\"";
                    lock (WhiteListCsvLines)
                    {
                        if (WhiteListCsvLines.Count < csvMaxLines + 1)
                            WhiteListCsvLines.Add(csvLine);
                    }
                    await realTimeWhiteListCsvCallback(csvLine);
                    processedIPs.TryAdd(ipAddress, true);
                }

                EnqueueSeed(new Seed(ip, newSourceType, version, port ?? 0, seed.Depth + 1, seed.OriginalSourceUrl, discoveredUrl));
            }

            private static string GetIpFromUrl(string url)
            {
                try
                {
                    Uri uri = new(url);
                    return uri.Host;
                }
                catch
                {
                    return string.Empty;
                }
            }

            private static async Task<string> DownloadHtmlContentAsync(string url, CancellationToken token)
            {
                using var client = new HttpClient();
                client.Timeout = TimeSpan.FromSeconds(10);
                var response = await client.GetAsync(url, token);
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStringAsync(CancellationToken.None);
            }

            private void EnqueueSeed(Seed seed)
            {
                if (processedIPs.TryAdd(seed.IP, true))
                    seedQueue.Enqueue(seed);
            }

            private static string EscapeCsvField(string field)
            {
                return field.Replace("\"", "\\\"");
            }
        }

        public static class SeedHelper
        {
            public static List<(string ip, int? port, string version)> ExtractIPAndPort(string text)
            {
                List<(string ip, int? port, string version)> results = new();
                string ipv4Pattern = @"\b(?<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::(?<port>[0-9]{1,5}))?\b";
                string ipv6Pattern = @"\b(?<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})(?::(?<port>[0-9]{1,5}))?\b";
                foreach (Match match in Regex.Matches(text, ipv4Pattern))
                {
                    string ip = match.Groups["ip"].Value;
                    int? port = match.Groups["port"].Success ? int.Parse(match.Groups["port"].Value) : (int?)null;
                    results.Add((ip, port, "ipv4"));
                }
                foreach (Match match in Regex.Matches(text, ipv6Pattern))
                {
                    string ip = match.Groups["ip"].Value;
                    int? port = match.Groups["port"].Success ? int.Parse(match.Groups["port"].Value) : (int?)null;
                    results.Add((ip, port, "ipv6"));
                }
                return results;
            }

            public static async Task<bool> IsActiveAndStaticAsync(string ip, int port, CancellationToken token)
            {
                string url = $"http://{ip}" + (port > 0 ? $":{port}" : "");
                try
                {
                    using var client = new HttpClient();
                    client.Timeout = TimeSpan.FromSeconds(5);
                    var response = await client.GetAsync(url, token);
                    if (response.StatusCode != HttpStatusCode.OK)
                        return false;
                    var finalUrl = response.RequestMessage?.RequestUri;
                    if (finalUrl != null)
                    {
                        string finalHostname = finalUrl.Host;
                        int finalPort = finalUrl.Port == -1 ? 80 : finalUrl.Port;
                        int expectedPort = port == 0 ? 80 : port;
                        if (finalHostname.Equals(ip) && finalPort == expectedPort)
                            return true;
                    }
                    return false;
                }
                catch
                {
                    return false;
                }
            }
        }

        public class Seed
        {
            public string IP { get; set; }
            public string SourceType { get; set; }
            public string Version { get; set; }
            public int? Port { get; set; }
            public int Depth { get; set; }
            public string OriginalSourceUrl { get; set; }
            public string DiscoveredUrl { get; set; }

            public Seed(string ip, string sourceType, string version, int? port = null, int depth = 0, string originalSourceUrl = "", string discoveredUrl = "")
            {
                IP = ip?.ToLower() ?? string.Empty;
                SourceType = sourceType ?? string.Empty;
                Version = version ?? string.Empty;
                Port = port;
                Depth = depth;
                OriginalSourceUrl = originalSourceUrl ?? string.Empty;
                DiscoveredUrl = discoveredUrl ?? string.Empty;
            }

            public string GetUrl()
            {
                return Port.HasValue && Port > 0 ? $"http://{IP}:{Port}" : $"http://{IP}";
            }

            public override string ToString()
            {
                return $"Seed({IP}{(Port.HasValue ? ":" + Port.ToString() : "")}, {SourceType}, {Version}, depth={Depth})";
            }
        }

        #endregion
    }
}
