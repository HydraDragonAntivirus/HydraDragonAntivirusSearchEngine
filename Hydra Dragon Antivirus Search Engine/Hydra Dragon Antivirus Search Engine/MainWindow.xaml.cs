using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using IOPath = System.IO.Path;

namespace Hydra_Dragon_Antivirus_Search_Engine
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        // Instead of a single list for each category, we now have eight lists.
        private readonly List<string> malwareFilesIPv4 = new();
        private readonly List<string> malwareFilesIPv6 = new();
        private readonly List<string> DDoSFilesIPv4 = new();
        private readonly List<string> DDoSFilesIPv6 = new();
        private readonly List<string> phishingFilesIPv4 = new();
        private readonly List<string> phishingFilesIPv6 = new();
        private readonly List<string> WhiteListFilesIPv4 = new();
        private readonly List<string> WhiteListFilesIPv6 = new();

        // Folder paths
        private string malwarePath = string.Empty;
        private string ddosPath = string.Empty;
        private string phishingPath = string.Empty;
        private string whiteListPath = string.Empty;
        // CSV folder paths:
        private string realTimeBulkPath = string.Empty;
        private string realTimeWhiteListPath = string.Empty;

        // Scanner instance – created when the user clicks Start Scan.
        private Scanner? scanner;
        // Cancellation token source to allow stopping the scan.
        private CancellationTokenSource cts = new();
        // A full log list to support search and saving.
        private readonly List<string> fullLogList = new();

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            // Cancel any ongoing scan operations.
            if (cts != null && !cts.IsCancellationRequested)
            {
                cts.Cancel();
            }
            // Stop log flush timer.
            StopLogFlusher();
            base.OnClosing(e);
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            StartLogFlusher();
            // Set default settings.
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

        #region Event Handlers

        private readonly ConcurrentQueue<string> logQueue = new();
        private System.Timers.Timer? logFlushTimer;

        private void StartLogFlusher()
        {
            // Flush every 300ms.
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
                            {
                                listBoxLog.Items.Add(log);
                            }
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

        private static readonly JsonSerializerOptions jsonOptions = new() { WriteIndented = true };

        // SaveSettingsAsync now uses asynchronous file I/O.
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
                RealTimeCsvWhiteListPath = realTimeWhiteListPath
            };

            string json = JsonSerializer.Serialize(settings, jsonOptions);
            await File.WriteAllTextAsync(filePath, json);
        }

        private void UpdateCurrentFileMessage(string message)
        {
            if (textBlockCurrentFile.Dispatcher.CheckAccess())
                textBlockCurrentFile.Text = message;
            else
                textBlockCurrentFile.Dispatcher.Invoke(() => textBlockCurrentFile.Text = message);
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

        // LoadSettingsAsync uses asynchronous file reading.
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
                    realTimeWhiteListPath = string.IsNullOrEmpty(settings.RealTimeCsvWhiteListPath)
                        ? (IOPath.GetDirectoryName(settings.RealTimeCsvWhiteListFile) ?? Environment.CurrentDirectory)
                        : settings.RealTimeCsvWhiteListPath;
                }
            }
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
                MessageBox.Show("Settings saved successfully.");
            }
        }

        private async void BtnLoadSettings_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new() { Filter = "JSON Files|*.json" };
            bool? result = ofd.ShowDialog();
            if (result == true)
            {
                await LoadSettingsAsync(ofd.FileName);
                MessageBox.Show("Settings loaded successfully.");
            }
        }

        // Asynchronously initialize (or clear) the realtime CSV files.
        private async Task InitializeRealtimeCsvFilesAsync()
        {
            if (checkBoxRealTimeCsvBulk.IsChecked == true && !string.IsNullOrEmpty(textBoxRealTimeCsvBulkFile.Text))
            {
                string? bulkDirectory = IOPath.GetDirectoryName(textBoxRealTimeCsvBulkFile.Text);
                if (!string.IsNullOrEmpty(bulkDirectory) && !Directory.Exists(bulkDirectory))
                {
                    Directory.CreateDirectory(bulkDirectory);
                }
                await File.WriteAllTextAsync(textBoxRealTimeCsvBulkFile.Text, string.Empty);
            }
            if (checkBoxRealTimeCsvWhiteList.IsChecked == true && !string.IsNullOrEmpty(textBoxRealTimeCsvWhiteListFile.Text))
            {
                string? whiteListDirectory = IOPath.GetDirectoryName(textBoxRealTimeCsvWhiteListFile.Text);
                if (!string.IsNullOrEmpty(whiteListDirectory) && !Directory.Exists(whiteListDirectory))
                {
                    Directory.CreateDirectory(whiteListDirectory);
                }
                await File.WriteAllTextAsync(textBoxRealTimeCsvWhiteListFile.Text, string.Empty);
            }
        }

        // Add a field to track the scan state.
        private bool isScanning = false;

        private async void BtnStartScan_Click(object sender, RoutedEventArgs e)
        {
            if (!isScanning)
            {
                isScanning = true;
                BtnStartScan.Content = "Stop Scan";
                try
                {
                    if (!int.TryParse(textBoxMaxDepth.Text, out int maxDepth))
                        maxDepth = 10;
                    if (!int.TryParse(textBoxMaxThreads.Text, out int maxThreads))
                        maxThreads = 100;
                    if (!int.TryParse(textBoxCsvMaxLines.Text, out int csvMaxLines))
                        csvMaxLines = 10000;
                    if (!int.TryParse(textBoxCsvMaxSize.Text, out int csvMaxSize))
                        csvMaxSize = 2097152;

                    string outputFileName = textBoxOutputFile.Text;
                    string whiteListOutputFileName = textBoxWhiteListOutputFile.Text;
                    string categoryMalicious = textBoxCategoryMalicious.Text;
                    string categoryPhishing = textBoxCategoryPhishing.Text;
                    string categoryDDoS = textBoxCategoryDDoS.Text;
                    string commentTemplate = textBoxCommentTemplate.Text;

                    bool scanKnownActive = checkBoxScanKnownActive.IsChecked.GetValueOrDefault();
                    bool allowAutoVerdict = checkBoxAllowAutoVerdict.IsChecked.GetValueOrDefault();

                    // Initialize realtime CSV files asynchronously.
                    await InitializeRealtimeCsvFilesAsync();
                    cts = new CancellationTokenSource();

                    // Scan IPv4.
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
                        scanKnownActive,
                        allowAutoVerdict,
                        "ipv4");

                    await scanner.StartScanAsync(cts.Token);

                    // Scan IPv6.
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
                        scanKnownActive,
                        allowAutoVerdict,
                        "ipv6");

                    await scanner.StartScanAsync(cts.Token);

                    // Finalize CSV output using Scanner's settings.
                    bool csvOk = await scanner.FinalizeCsvFilesAsync();
                    if (!csvOk)
                        MessageBox.Show("CSV output exceeds the defined limits.");
                    else
                        MessageBox.Show("Scan completed and CSV files generated successfully.");
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

        #endregion

        #region Malware IPv4 List Handlers
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
                    MessageBox.Show("File is not a txt file.");
            }
            else
                MessageBox.Show("File does not exist.");
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
        #endregion

        #region Malware IPv6 List Handlers
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
                    MessageBox.Show("File is not a txt file.");
            }
            else
                MessageBox.Show("File does not exist.");
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
        #endregion

        #region DDoS IPv4 List Handlers
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
                    MessageBox.Show("File is not a txt file.");
            }
            else
                MessageBox.Show("File does not exist.");
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
        #endregion

        #region DDoS IPv6 List Handlers
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
                    MessageBox.Show("File is not a txt file.");
            }
            else
                MessageBox.Show("File does not exist.");
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
        #endregion

        #region Phishing IPv4 List Handlers
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
                    MessageBox.Show("File is not a txt file.");
            }
            else
                MessageBox.Show("File does not exist.");
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
        #endregion

        #region Phishing IPv6 List Handlers
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
                    MessageBox.Show("File is not a txt file.");
            }
            else
                MessageBox.Show("File does not exist.");
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
        #endregion

        #region WhiteList IPv4 List Handlers
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
                    MessageBox.Show("File is not a txt file.");
            }
            else
                MessageBox.Show("File does not exist.");
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
        #endregion

        #region WhiteList IPv6 List Handlers
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
                    MessageBox.Show("File is not a txt file.");
            }
            else
                MessageBox.Show("File does not exist.");
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
        #endregion

        #region UI Helper Methods
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
                                {
                                    await listBoxLog.Dispatcher.InvokeAsync(() =>
                                        logQueue.Enqueue("Error saving realtime log: " + ex.Message));
                                }
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
            public List<string> MalwareFiles { get; set; } = new();
            public List<string> DDoSFiles { get; set; } = new();
            public List<string> PhishingFiles { get; set; } = new();
            public List<string> WhiteListFiles { get; set; } = new();
            public string MalwarePath { get; set; } = string.Empty;
            public string DDoSPath { get; set; } = string.Empty;
            public string PhishingPath { get; set; } = string.Empty;
            public string WhiteListPath { get; set; } = string.Empty;
            public string RealTimeCsvBulkPath { get; set; } = string.Empty;
            public string RealTimeCsvWhiteListPath { get; set; } = string.Empty;

            public List<string> MalwareFilesIPv4 { get; set; } = new();
            public List<string> MalwareFilesIPv6 { get; set; } = new();
            public List<string> DDoSFilesIPv4 { get; set; } = new();
            public List<string> DDoSFilesIPv6 { get; set; } = new();
            public List<string> PhishingFilesIPv4 { get; set; } = new();
            public List<string> PhishingFilesIPv6 { get; set; } = new();
            public List<string> WhiteListFilesIPv4 { get; set; } = new();
            public List<string> WhiteListFilesIPv6 { get; set; } = new();
        }

        #endregion

        /// <summary>
        /// Scanner class: Loads seeds, performs HTTP scans concurrently, recursively discovers IPs,
        /// and builds two CSV reports.
        /// </summary>
        public partial class Scanner
        {
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
            public List<string> BulkCsvLines { get; private set; } = new List<string>();
            public List<string> WhiteListCsvLines { get; private set; } = new List<string>();
            private readonly ConcurrentQueue<Seed> seedQueue = new();
            private readonly ConcurrentDictionary<string, bool> processedIPs = new();
            int totalSeeds = 0;
            int processedCount = 0;
            private readonly HttpClient httpClient = new();
            private readonly bool scanKnownActive;
            private readonly bool allowAutoVerdict;

            // Lock for thread-safe updates to BulkCsvLines.
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
                bool scanKnownActive = false,
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
                this.commentTemplate = commentTemplate ?? "Related with ip address detected by heuristics of https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine (Source IP: {ip}, Source URL: {source_url}, Discovered URL: {discovered_url}, Verdict: {verdict})";
                this.scanProgressCallback = scanProgressCallback;
                this.scanKnownActive = scanKnownActive;
                this.allowAutoVerdict = allowAutoVerdict;
                this.SelectedIPType = selectedIPType;
            }

            public async Task<bool> FinalizeCsvFilesAsync()
            {
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
                    // Priority order: WhiteList, Phishing, DDoS, Malicious.
                    await LoadSeedsFromFileListAsync(WhiteListFiles, "whitelist", token);
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
                foreach (var file in fileList.Where(file => Path.GetExtension(file)
                                 .Equals(".txt", StringComparison.OrdinalIgnoreCase)))
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
                        // Yield to allow UI processing
                        await Task.Yield();
                    }
                    else
                    {
                        break;
                    }
                }
            }

            private async Task ProcessSeedAsync(Seed seed, CancellationToken token)
            {
                if (seed.Depth > maxDepth)
                    return;

                string url = seed.GetUrl();
                logCallback("Processing: " + url);

                try
                {
                    // For seeds at depth 0 with ScanKnownActive disabled, perform the HTTP request and extract new seeds
                    // so that progress is updated, but do not add the CSV scan result.
                    if (!scanKnownActive && seed.Depth == 0)
                    {
                        var response = await httpClient.GetAsync(url, token);
                        if (!response.IsSuccessStatusCode)
                        {
                            logCallback($"Failed: {url} Status: {response.StatusCode}");
                            return;
                        }

                        string content = await response.Content.ReadAsStringAsync(token);
                        if (string.IsNullOrEmpty(content))
                            return;

                        logCallback("Visited: " + url);

                        // Process discovered IPs (depth will increase for new seeds)
                        if (seed.Depth < maxDepth)
                        {
                            var tasks = new List<Task>();

                            // Process IPv4 matches
                            string ipv4Pattern = @"\b(?<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::(?<port>[0-9]{1,5}))?\b";
                            foreach (Match m in Regex.Matches(content, ipv4Pattern))
                            {
                                tasks.Add(ProcessMatch(m, "ipv4", url, m.Value, seed.SourceType, seed.Depth, token));
                            }

                            // Process IPv6 matches
                            string ipv6Pattern = @"\b(?<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})(?::(?<port>[0-9]{1,5}))?\b";
                            foreach (Match m in Regex.Matches(content, ipv6Pattern))
                            {
                                tasks.Add(ProcessMatch(m, "ipv6", url, m.Value, seed.SourceType, seed.Depth, token));
                            }

                            await Task.WhenAll(tasks);
                        }
                        return;
                    }

                    // For seeds at depth > 0 with ScanKnownActive disabled, skip if the URLs are identical.
                    if (!scanKnownActive && seed.Depth > 0 && seed.OriginalSourceUrl == seed.DiscoveredUrl)
                    {
                        logCallback($"Skipping scan at depth {seed.Depth}: Source URL and Discovered URL are the same: {seed.OriginalSourceUrl}");
                        return;
                    }

                    // Normal processing for seeds that are either depth > 0 with ScanKnownActive enabled or
                    // any seed when ScanKnownActive is enabled.
                    var normalResponse = await httpClient.GetAsync(url, token);
                    if (!normalResponse.IsSuccessStatusCode)
                    {
                        logCallback($"Failed: {url} Status: {normalResponse.StatusCode}");
                        return;
                    }

                    string normalContent = await normalResponse.Content.ReadAsStringAsync(token);
                    if (string.IsNullOrEmpty(normalContent))
                        return;

                    logCallback("Visited: " + url);

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
                        .Replace("{verdict}", seed.SourceType);

                    if (comment.Length > 1024)
                        comment = comment[..1024];

                    string csvLine = $"{seed.IP},\"{category}\",{reportDate},\"{EscapeCsvField(comment)}\"";
                    // Add the CSV line to scan results.
                    lock (bulkCsvLock)
                    {
                        BulkCsvLines.Add(csvLine);
                    }
                    await realTimeBulkCsvCallback(csvLine);

                    if (seed.Depth < maxDepth)
                    {
                        var tasks = new List<Task>();

                        // Process IPv4 matches
                        string ipv4Pattern = @"\b(?<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::(?<port>[0-9]{1,5}))?\b";
                        foreach (Match m in Regex.Matches(normalContent, ipv4Pattern))
                        {
                            tasks.Add(ProcessMatch(m, "ipv4", url, m.Value, seed.SourceType, seed.Depth, token));
                        }

                        // Process IPv6 matches
                        string ipv6Pattern = @"\b(?<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})(?::(?<port>[0-9]{1,5}))?\b";
                        foreach (Match m in Regex.Matches(normalContent, ipv6Pattern))
                        {
                            tasks.Add(ProcessMatch(m, "ipv6", url, m.Value, seed.SourceType, seed.Depth, token));
                        }

                        await Task.WhenAll(tasks);
                    }
                }
                catch (Exception ex)
                {
                    logCallback("Error processing " + url + ": " + ex.Message);
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

            private async Task ProcessIPAsync(Seed seed, string ip, int? port, string version, string discoveredUrl, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                if (processedIPs.ContainsKey(ip))
                    return;

                string newSourceType = seed.SourceType;

                // Log the current depth level
                logCallback($"Processing IP: {ip} at Depth: {seed.Depth} from URL: {discoveredUrl}");

                // Check if allowAutoVerdict is true
                if (allowAutoVerdict)
                {
                    bool active = await SeedHelper.IsActiveAndStaticAsync(ip, port ?? 0, token);
                    if (!active)
                    {
                        // Benign Auto Verdict 3: Dead IP (inactive or non-static)
                        newSourceType = "benign (auto verdict 3)";
                        string reportDate = DateTime.UtcNow.ToString("o");
                        string comment = $"Auto-WhiteListed dead IP from {seed.OriginalSourceUrl}";
                        string csvLine = $"{ip},\"WhiteList\",{reportDate},\"{EscapeCsvField(comment)}\"";

                        lock (WhiteListCsvLines)
                        {
                            // Add the line to the whitelist CSV if within size limits
                            if (WhiteListCsvLines.Count < csvMaxLines + 1)
                                WhiteListCsvLines.Add(csvLine);
                        }

                        await realTimeWhiteListCsvCallback(csvLine);
                        return; // Skip adding this IP to the bulk CSV as it's whitelisted
                    }
                    else
                    {
                        // Benign Auto Verdict 2: Active and Static IP (related to a benign URL)
                        newSourceType = "benign (auto verdict 2)";
                        string reportDate = DateTime.UtcNow.ToString("o");
                        string comment = $"Active and static IP from {seed.OriginalSourceUrl} marked as benign";
                        string csvLine = $"{ip},\"WhiteList\",{reportDate},\"{EscapeCsvField(comment)}\"";

                        lock (WhiteListCsvLines)
                        {
                            // Add the line to the whitelist CSV if within size limits
                            if (WhiteListCsvLines.Count < csvMaxLines + 1)
                                WhiteListCsvLines.Add(csvLine);
                        }

                        await realTimeWhiteListCsvCallback(csvLine);
                        return; // Skip adding this IP to the bulk CSV as it's whitelisted
                    }
                }

                // Benign Auto Verdict 1: For malicious IPs that are no longer active/static
                if (seed.SourceType == "malicious")
                {
                    newSourceType = "benign (auto verdict 1)";
                    string reportDate = DateTime.UtcNow.ToString("o");
                    string comment = $"Malicious IP {ip} is no longer active/static, marked as benign";
                    string csvLine = $"{ip},\"WhiteList\",{reportDate},\"{EscapeCsvField(comment)}\"";

                    lock (WhiteListCsvLines)
                    {
                        // Add the line to the whitelist CSV if within size limits
                        if (WhiteListCsvLines.Count < csvMaxLines + 1)
                            WhiteListCsvLines.Add(csvLine);
                    }

                    await realTimeWhiteListCsvCallback(csvLine);
                    return; // Skip adding this IP to the bulk CSV as it's whitelisted
                }

                // Only add to the Bulk CSV if it's not in the whitelist
                if (newSourceType != "WhiteList")
                {
                    string reportDate = DateTime.UtcNow.ToString("o");
                    string comment = $"IP processed from {seed.OriginalSourceUrl}";
                    string csvLine = $"{ip},\"{newSourceType}\",{reportDate},\"{EscapeCsvField(comment)}\"";

                    lock (bulkCsvLock)
                    {
                        BulkCsvLines.Add(csvLine);
                    }
                    await realTimeBulkCsvCallback(csvLine);
                }

                // Discover new IPs from the HTML content of the discovered URL
                try
                {
                    var content = await DownloadHtmlContentAsync(discoveredUrl, token);

                    // Extract IPv4 and IPv6 IPs from the content
                    var newIPs = ExtractIPsFromHtml(content);
                    foreach (var newIp in newIPs)
                    {
                        // Enqueue each new discovered IP for processing
                        EnqueueSeed(new Seed(newIp, "unknown", version, port ?? 0, seed.Depth + 1, seed.OriginalSourceUrl, discoveredUrl));
                    }
                }
                catch (Exception ex)
                {
                    logCallback($"Error fetching content from {discoveredUrl}: {ex.Message}");
                }

                // Enqueue the seed for further processing if not auto-whitelisted
                EnqueueSeed(new Seed(ip, newSourceType, version, port ?? 0, seed.Depth + 1, seed.OriginalSourceUrl, discoveredUrl));
            }

            private async Task<string> DownloadHtmlContentAsync(string url, CancellationToken token)
            {
                using (var client = new HttpClient())
                {
                    client.Timeout = TimeSpan.FromSeconds(10);
                    var response = await client.GetAsync(url, token);
                    if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"Failed to fetch content from {url}");
                    }
                    return await response.Content.ReadAsStringAsync();
                }
            }

            private List<string> ExtractIPsFromHtml(string htmlContent)
            {
                var ips = new List<string>();

                // Regex patterns for IPv4 and IPv6
                string ipv4Pattern = @"\b(?:\d{1,3}\.){3}\d{1,3}\b";
                string ipv6Pattern = @"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b";

                // Find all IPs in the HTML content
                var ipv4Matches = Regex.Matches(htmlContent, ipv4Pattern);
                var ipv6Matches = Regex.Matches(htmlContent, ipv6Pattern);

                // Add matched IPs to the list
                foreach (Match match in ipv4Matches)
                {
                    ips.Add(match.Value);
                }
                foreach (Match match in ipv6Matches)
                {
                    ips.Add(match.Value);
                }

                return ips;
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
                    using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                    HttpResponseMessage response = await httpClient.GetAsync(url, token);
                    if (!response.IsSuccessStatusCode)
                        return false;
                    Uri? finalUri = response.RequestMessage?.RequestUri;
                    if (finalUri == null)
                        return false;
                    string finalHostname = finalUri.Host;
                    int finalPort = finalUri.Port > 0 ? finalUri.Port : 80;
                    int expectedPort = port > 0 ? port : 80;
                    if (!string.IsNullOrEmpty(finalHostname) &&
                        IPAddress.TryParse(finalHostname, out _) &&
                        finalHostname == ip &&
                        finalPort == expectedPort)
                    {
                        return true;
                    }
                    return false;
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }

        public record Seed(
            string IP,
            string SourceType,
            string Version,
            int? Port,
            int Depth,
            string OriginalSourceUrl,
            string DiscoveredUrl)
        {
            public string GetUrl() =>
                Port.HasValue ? $"http://{IP}:{Port}" : $"http://{IP}";
        }

        // Filters the log listbox based on the search term.
        private void TextBoxSearch_TextChanged(object sender, RoutedEventArgs e)
        {
            string filter = TextBoxSearch.Text;
            listBoxLog.Items.Clear();
            foreach (string entry in fullLogList)
            {
                if (entry.Contains(filter, StringComparison.OrdinalIgnoreCase))
                {
                    listBoxLog.Items.Add(entry);
                }
            }
        }

        private void BtnClearLog_Click(object sender, RoutedEventArgs e)
        {
            listBoxLog.Items.Clear();
        }

        // Save log asynchronously.
        private async void BtnSaveLog_Click(object sender, RoutedEventArgs e)
        {
            var sfd = new SaveFileDialog { Filter = "Text Files|*.txt" };
            bool? result = sfd.ShowDialog();
            if (result == true)
            {
                await File.WriteAllLinesAsync(sfd.FileName, fullLogList);
                MessageBox.Show("Log saved successfully.");
            }
        }

        // Asynchronous callbacks for writing CSV lines.
        private async Task AppendBulkCsvLineToFileAsync(string csvLine)
        {
            bool isRealTimeEnabled = false;
            string fileName = string.Empty;

            // Use the Dispatcher to safely read UI elements.
            await textBoxRealTimeCsvBulkFile.Dispatcher.InvokeAsync(() =>
            {
                isRealTimeEnabled = checkBoxRealTimeCsvBulk.IsChecked == true;
                fileName = textBoxRealTimeCsvBulkFile.Text;
            });

            if (isRealTimeEnabled && !string.IsNullOrEmpty(fileName))
            {
                string? directory = IOPath.GetDirectoryName(fileName);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
                try
                {
                    await File.AppendAllTextAsync(fileName, csvLine + Environment.NewLine);
                }
                catch (Exception ex)
                {
                    // Display error on the UI thread.
                    await textBoxRealTimeCsvBulkFile.Dispatcher.InvokeAsync(() =>
                    {
                        MessageBox.Show("Error saving Bulk CSV line: " + ex.Message + " " + ex.StackTrace,
                            "Bulk CSV Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
        }

        private readonly object WhiteListCsvLock = new();
        private async Task AppendWhiteListCsvLineToFileAsync(string csvLine)
        {
            bool isRealTimeEnabled = false;
            string fileName = string.Empty;

            // Use the Dispatcher to safely read UI elements.
            await textBoxRealTimeCsvWhiteListFile.Dispatcher.InvokeAsync(() =>
            {
                isRealTimeEnabled = checkBoxRealTimeCsvWhiteList.IsChecked == true;
                fileName = textBoxRealTimeCsvWhiteListFile.Text;
            });

            if (isRealTimeEnabled && !string.IsNullOrEmpty(fileName))
            {
                string? directory = IOPath.GetDirectoryName(fileName);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
                lock (WhiteListCsvLock)
                {
                    File.AppendAllText(fileName, csvLine + Environment.NewLine);
                }
                await Task.CompletedTask;
            }
        }
    }
}
