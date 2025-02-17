using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using Microsoft.Win32;
using IOPath = System.IO.Path;

namespace Hydra_Dragon_Antivirus_Search_Engine
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
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
        private CancellationTokenSource cts = new CancellationTokenSource();
        // A full log list to support search and saving.
        private readonly List<string> fullLogList = new();

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // Set default settings – these values are user-configurable in the UI.
            textBoxMaxDepth.Text = "10";
            textBoxMaxThreads.Text = "100";
            textBoxCsvMaxLines.Text = "10000"; // Maximum lines (including header)
            textBoxCsvMaxSize.Text = "2097152"; // 2 MB in bytes
            textBoxOutputFile.Text = "BulkReport.csv";
            textBoxWhiteListOutputFile.Text = "WhiteListReport.csv";

            textBoxCategoryMalicious.Text = "20";
            textBoxCategoryPhishing.Text = "7";
            textBoxCategoryDDoS.Text = "18";
            textBoxCommentTemplate.Text = "Related with ip address detected by heuristics of https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine (Source IP: {ip}, Source URL: {source_url}, Discovered URL: {discovered_url}, Verdict: {verdict})";
        }

        #region Event Handlers (as referenced in Designer)

        private static readonly JsonSerializerOptions jsonOptions = new() { WriteIndented = true };

        private void SaveSettings(string filePath)
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

                // Save the eight lists:
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
            File.WriteAllText(filePath, json);
        }

        private void UpdateCurrentFileMessage(string message)
        {
            if (textBlockCurrentFile.Dispatcher.CheckAccess())
                textBlockCurrentFile.Text = message;
            else
                textBlockCurrentFile.Dispatcher.Invoke(() => textBlockCurrentFile.Text = message);
        }

        private string ConvertToAbsolutePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return path;
            if (IOPath.IsPathRooted(path))
                return IOPath.GetFullPath(path);
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            return IOPath.GetFullPath(IOPath.Combine(baseDir, path));
        }

        private void LoadSettings(string filePath)
        {
            if (File.Exists(filePath))
            {
                string json = File.ReadAllText(filePath);
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

                    // Load eight lists.
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

                    // Update UI listboxes – assume your XAML now defines separate listboxes.
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
            SaveFileDialog sfd = new SaveFileDialog()
            {
                Filter = "Text Files|*.txt|All Files|*.*",
                Title = "Select Real-Time Log File"
            };
            if (sfd.ShowDialog() == true)
                textBoxRealTimeFile.Text = sfd.FileName;
        }

        private void BtnBrowseOutputFile_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog()
            {
                Filter = "CSV Files|*.csv|All Files|*.*",
                Title = "Select Output File"
            };
            if (sfd.ShowDialog() == true)
                textBoxOutputFile.Text = sfd.FileName;
        }

        private void BtnBrowseWhiteListOutputFile_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog()
            {
                Filter = "CSV Files|*.csv|All Files|*.*",
                Title = "Select WhiteList Output File"
            };
            if (sfd.ShowDialog() == true)
                textBoxWhiteListOutputFile.Text = sfd.FileName;
        }

        private void BtnBrowseBulkCsv_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog()
            {
                Filter = "CSV Files|*.csv|All Files|*.*",
                Title = "Select Real-Time Bulk CSV File"
            };
            if (sfd.ShowDialog() == true)
                textBoxRealTimeCsvBulkFile.Text = sfd.FileName;
        }

        private void BtnBrowseWhiteListCsv_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog()
            {
                Filter = "CSV Files|*.csv|All Files|*.*",
                Title = "Select Real-Time WhiteList CSV File"
            };
            if (sfd.ShowDialog() == true)
                textBoxRealTimeCsvWhiteListFile.Text = sfd.FileName;
        }

        private void BtnSaveSettings_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog() { Filter = "JSON Files|*.json" };
            if (sfd.ShowDialog() == true)
            {
                SaveSettings(sfd.FileName);
                MessageBox.Show("Settings saved successfully.");
            }
        }

        private void BtnLoadSettings_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog() { Filter = "JSON Files|*.json" };
            bool? result = ofd.ShowDialog();
            if (result == true)
            {
                LoadSettings(ofd.FileName);
                MessageBox.Show("Settings loaded successfully.");
            }
        }

        private async void BtnStartScan_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(textBoxMaxDepth.Text, out int maxDepth)) maxDepth = 10;
            if (!int.TryParse(textBoxMaxThreads.Text, out int maxThreads)) maxThreads = 100;
            if (!int.TryParse(textBoxCsvMaxLines.Text, out int csvMaxLines)) csvMaxLines = 10000;
            if (!int.TryParse(textBoxCsvMaxSize.Text, out int csvMaxSize)) csvMaxSize = 2097152;

            string outputFileName = textBoxOutputFile.Text;
            string whiteListOutputFileName = textBoxWhiteListOutputFile.Text;
            string categoryMalicious = textBoxCategoryMalicious.Text;
            string categoryPhishing = textBoxCategoryPhishing.Text;
            string categoryDDoS = textBoxCategoryDDoS.Text;
            string commentTemplate = textBoxCommentTemplate.Text;

            bool scanKnownActive = checkBoxScanKnownActive.IsChecked.GetValueOrDefault();
            bool allowAutoVerdict = checkBoxAllowAutoVerdict.IsChecked.GetValueOrDefault();

            // Scan IPv4:
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
                AppendBulkCsvLineToFile,
                AppendWhiteListCsvLineToFile,
                commentTemplate,
                UpdateCurrentFileMessage,  // scan progress callback
                scanKnownActive,
                allowAutoVerdict,
                "ipv4");
            await Task.Run(async () => { await scanner.StartScanAsync(cts!.Token); });

            // Scan IPv6:
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
                AppendBulkCsvLineToFile,
                AppendWhiteListCsvLineToFile,
                commentTemplate,
                UpdateCurrentFileMessage,  // scan progress callback
                scanKnownActive,
                allowAutoVerdict,
                "ipv6");
            await Task.Run(async () => { await scanner.StartScanAsync(cts!.Token); });

            int totalLines = scanner.BulkCsvLines.Count;
            string csvContent = string.Join("\n", scanner.BulkCsvLines);
            int csvSizeInBytes = Encoding.UTF8.GetByteCount(csvContent);

            if (totalLines > csvMaxLines + 1)
                MessageBox.Show("CSV output exceeds the maximum allowed number of lines (" + csvMaxLines + ").");
            else if (csvSizeInBytes > csvMaxSize)
                MessageBox.Show("CSV output exceeds the maximum allowed file size (" + csvMaxSize + " bytes).");
            else
            {
                File.WriteAllLines(outputFileName, scanner.BulkCsvLines, Encoding.UTF8);
                File.WriteAllLines(whiteListOutputFileName, scanner.WhiteListCsvLines, Encoding.UTF8);
                MessageBox.Show("Scan completed and CSV files generated successfully.");
            }
        }

        private void BtnStopScan_Click(object sender, RoutedEventArgs e)
        {
            if (cts != null)
            {
                cts.Cancel();
                UpdateLog("Scan cancellation requested.");
            }
        }
        #endregion

        #region Malware IPv4 List Handlers
        private void BtnBrowseMalwareIPv4_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog()
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
            OpenFileDialog ofd = new OpenFileDialog()
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
            OpenFileDialog ofd = new OpenFileDialog()
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
            OpenFileDialog ofd = new OpenFileDialog()
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
            OpenFileDialog ofd = new OpenFileDialog()
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
            OpenFileDialog ofd = new OpenFileDialog()
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
            OpenFileDialog ofd = new OpenFileDialog()
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
            OpenFileDialog ofd = new OpenFileDialog()
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
        private bool realtimeLogErrorShown = false;
        private async void UpdateLog(string message)
        {
            string logEntry = $"{DateTime.Now}: {message}";
            fullLogList.Add(logEntry);
            listBoxLog.Dispatcher.Invoke(() => listBoxLog.Items.Add(logEntry));

            bool isRealTimeSaveEnabled = false;
            string realTimeFilePath = "";
            await listBoxLog.Dispatcher.InvokeAsync(() =>
            {
                isRealTimeSaveEnabled = checkBoxRealTimeSave.IsChecked == true;
                realTimeFilePath = textBoxRealTimeFile.Text;
            });

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
                    catch (Exception ex)
                    {
                        attempt++;
                        if (attempt >= maxRetries)
                        {
                            if (!realtimeLogErrorShown)
                            {
                                realtimeLogErrorShown = true;
                                listBoxLog.Dispatcher.Invoke(() =>
                                    listBoxLog.Items.Add("Error saving realtime log: " + ex.Message));
                            }
                        }
                        else
                        {
                            await Task.Delay(100); // Wait before retrying
                        }
                    }
                }
            }
        }

        private void UpdateProgress(int current, int total)
        {
            if (progressBarScan.Dispatcher.CheckAccess())
            {
                progressBarScan.Maximum = total;
                progressBarScan.Value = current;
                textBlockProgress.Text = $"{current} / {total}";
            }
            else
            {
                progressBarScan.Dispatcher.Invoke(new Action(() =>
                {
                    progressBarScan.Maximum = total;
                    progressBarScan.Value = current;
                    textBlockProgress.Text = $"{current} / {total}";
                }));
            }
        }

        private bool realtimeBulkCsvErrorShown = false;
        private void AppendBulkCsvLineToFile(string csvLine)
        {
            // Make sure checkBoxRealTimeCsvBulk and textBoxRealTimeCsvBulkFile exist on your form.
            if (checkBoxRealTimeCsvBulk.IsChecked == true && !string.IsNullOrEmpty(textBoxRealTimeCsvBulkFile.Text))
            {
                try
                {
                    File.AppendAllText(textBoxRealTimeCsvBulkFile.Text, csvLine + Environment.NewLine);
                }
                catch (Exception ex)
                {
                    if (!realtimeBulkCsvErrorShown)
                    {
                        realtimeBulkCsvErrorShown = true;
                        MessageBox.Show("Error saving Bulk CSV line: " + ex.Message + " " + ex.StackTrace, "Bulk CSV Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        private readonly object WhiteListCsvLock = new();
        private void AppendWhiteListCsvLineToFile(string csvLine)
        {
            if (checkBoxRealTimeCsvWhiteList.IsChecked == true && !string.IsNullOrEmpty(textBoxRealTimeCsvWhiteListFile.Text))
            {
                lock (WhiteListCsvLock)
                {
                    File.AppendAllText(textBoxRealTimeCsvWhiteListFile.Text, csvLine + Environment.NewLine);
                }
            }
        }
        #endregion

        #region Scanner and Helper Classes

        public class IpFileSetting
        {
            public string FileName { get; set; } = string.Empty;
            public bool IsChecked { get; set; }
        }

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

            public List<IpFileSetting> IPv4Files { get; set; } = new();
            public List<IpFileSetting> IPv6Files { get; set; } = new();

            // Added eight separate file lists:
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
        /// Scanner class:
        /// Loads seeds from files (from three lists), performs HTTP scans concurrently, recursively discovers IPs,
        /// and builds two CSV reports (one for bulk results and one for WhiteListed IPs).
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
            private readonly Action<string> scanProgressCallback;

            public List<string> BulkCsvLines { get; private set; } = new List<string>();
            public List<string> WhiteListCsvLines { get; private set; } = new List<string>();

            // Concurrent collections for seeds.
            private readonly ConcurrentQueue<Seed> seedQueue = new();
            private readonly ConcurrentDictionary<string, bool> processedIPs = new();

            // HashSets to track WhiteListed and blacklisted IPs.
            private readonly HashSet<string> WhiteListedIPs = new(StringComparer.OrdinalIgnoreCase);
            private readonly HashSet<string> blacklistIPs = new(StringComparer.OrdinalIgnoreCase);

            int totalSeeds = 0;
            int processedCount = 0;
            private readonly HttpClient httpClient = new();

            private readonly Action<string> realTimeBulkCsvCallback;
            private readonly Action<string> realTimeWhiteListCsvCallback;
            private readonly bool scanKnownActive;
            private readonly bool allowAutoVerdict;

            // Constructor – note that any UI callbacks for IPv4/IPv6 have been removed.
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
                Action<string> realTimeBulkCsvCallback,
                Action<string> realTimeWhiteListCsvCallback,
                string commentTemplate,
                Action<string> scanProgressCallback,
                bool scanKnownActive = false,
                bool allowAutoVerdict = false,
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

            private async Task ProcessWhiteListFileAsync(string file, CancellationToken token)
            {
                List<string> WhiteListSites = new();
                using (var reader = new StreamReader(file))
                {
                    string? line;
                    while ((line = await reader.ReadLineAsync(token)) is not null)
                    {
                        token.ThrowIfCancellationRequested();
                        string trimmed = line.Trim();
                        if (string.IsNullOrEmpty(trimmed))
                            continue;

                        if (IPAddress.TryParse(trimmed, out _))
                        {
                            lock (WhiteListedIPs)
                            {
                                WhiteListedIPs.Add(trimmed);
                            }
                        }
                        else
                        {
                            WhiteListSites.Add(trimmed);
                        }
                    }
                }

                var tasks = new List<Task>();
                using var semaphore = new SemaphoreSlim(maxThreads);
                foreach (var url in WhiteListSites)
                {
                    token.ThrowIfCancellationRequested();
                    string actualUrl = Uri.IsWellFormedUriString(url, UriKind.Absolute) ? url : "http://" + url;
                    await semaphore.WaitAsync(token);
                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            token.ThrowIfCancellationRequested();
                            var response = await httpClient.GetAsync(actualUrl, token);
                            if (response.IsSuccessStatusCode)
                            {
                                string content = await response.Content.ReadAsStringAsync();
                                var foundIPs = SeedHelper.ExtractIPAndPort(content);
                                foreach (var (ip, port, version) in foundIPs)
                                {
                                    token.ThrowIfCancellationRequested();
                                    if (blacklistIPs.Contains(ip))
                                    {
                                        logCallback($"IP {ip} from WhiteList site {actualUrl} is in the blacklist; skipping.");
                                        continue;
                                    }
                                    lock (WhiteListedIPs)
                                    {
                                        if (WhiteListedIPs.Add(ip))
                                        {
                                            string reportDate = DateTime.UtcNow.ToString("o");
                                            string comment = $"WhiteList site visited: {actualUrl}";
                                            string csvLine = $"{ip},\"WhiteList (visited)\",{reportDate},\"{EscapeCsvField(comment)}\"";
                                            lock (WhiteListCsvLines)
                                            {
                                                if (WhiteListCsvLines.Count < csvMaxLines + 1)
                                                    WhiteListCsvLines.Add(csvLine);
                                            }
                                            realTimeWhiteListCsvCallback?.Invoke(csvLine);
                                        }
                                    }
                                }
                            }
                            else
                            {
                                logCallback($"Failed to visit WhiteList site: {actualUrl} Status: {response.StatusCode}");
                            }
                        }
                        catch (Exception ex)
                        {
                            logCallback($"Error visiting WhiteList site: {actualUrl} Exception: {ex.Message}");
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }, token));
                }
                await Task.WhenAll(tasks);
            }

            public async Task StartScanAsync(CancellationToken token)
            {
                try
                {
                    foreach (var file in WhiteListFiles.Where(file => IOPath.GetExtension(file)
                                 .Equals(".txt", StringComparison.OrdinalIgnoreCase)))
                    {
                        await ProcessWhiteListFileAsync(file, token);
                    }

                    // Priority order: Phishing, DDoS, Malicious.
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

            private async Task ProcessIPLine(string ip, int? port, string version, string file, string trimmed, string defaultSourceType)
            {
                if (!processedIPs.TryAdd(ip, true))
                    return;

                bool isWhiteListed = WhiteListedIPs.Contains(ip);
                if (isWhiteListed)
                {
                    string reportDate = DateTime.UtcNow.ToString("o");
                    string comment = $"WhiteList from file: {file}";
                    string csvLine = $"{ip},\"WhiteList\",{reportDate},\"{EscapeCsvField(comment)}\"";
                    lock (WhiteListCsvLines)
                    {
                        if (WhiteListCsvLines.Count < csvMaxLines + 1)
                            WhiteListCsvLines.Add(csvLine);
                    }
                    realTimeWhiteListCsvCallback?.Invoke(csvLine);
                }
                else
                {
                    string discoveredUrl;
                    if (!scanKnownActive)
                    {
                        discoveredUrl = trimmed + "_discovered";
                        while (malwareFiles.Contains(discoveredUrl) ||
                               DDoSFiles.Contains(discoveredUrl) ||
                               phishingFiles.Contains(discoveredUrl) ||
                               WhiteListFiles.Contains(discoveredUrl))
                        {
                            discoveredUrl += "_x";
                        }
                    }
                    else
                    {
                        discoveredUrl = trimmed;
                    }
                    seedQueue.Enqueue(new Seed(ip, defaultSourceType, version, port, 1, trimmed, discoveredUrl));
                }
                await Task.CompletedTask;
            }

            private async Task LoadSeedsFromFileListAsync(List<string> fileList, string defaultSourceType, CancellationToken token)
            {
                foreach (var file in fileList.Where(file => IOPath.GetExtension(file)
                             .Equals(".txt", StringComparison.OrdinalIgnoreCase)))
                {
                    if (token.IsCancellationRequested)
                        return;

                    scanProgressCallback($"Current Loaded Definition File: {file}");
                    logCallback($"Loading file: {file}");

                    // Load all lines at once
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
                        await ProcessIPLine(ip, port, SelectedIPType.ToLower(), file, trimmed, defaultSourceType);
                    }
                    logCallback($"Finished loading file: {file}");
                }
            }

            private async Task ProcessMatch(Match match, string version, string file, string trimmed, string defaultSourceType)
            {
                string ip = match.Groups["ip"].Value;
                int? port = match.Groups["port"].Success ? (int?)int.Parse(match.Groups["port"].Value) : null;
                if (!processedIPs.TryAdd(ip, true))
                    return;

                bool isWhiteListed = WhiteListedIPs.Contains(ip);
                if (isWhiteListed)
                {
                    string reportDate = DateTime.UtcNow.ToString("o");
                    string comment = $"WhiteListed from file: {file}";
                    string csvLine = $"{ip},\"WhiteList\",{reportDate},\"{EscapeCsvField(comment)}\"";
                    lock (WhiteListCsvLines)
                    {
                        if (WhiteListCsvLines.Count < csvMaxLines + 1)
                            WhiteListCsvLines.Add(csvLine);
                    }
                    realTimeWhiteListCsvCallback?.Invoke(csvLine);
                }
                else
                {
                    string discoveredUrl;
                    if (!scanKnownActive)
                    {
                        discoveredUrl = trimmed + "_discovered";
                        while (malwareFiles.Contains(discoveredUrl) ||
                               DDoSFiles.Contains(discoveredUrl) ||
                               phishingFiles.Contains(discoveredUrl) ||
                               WhiteListFiles.Contains(discoveredUrl))
                        {
                            discoveredUrl += "_x";
                        }
                    }
                    else
                    {
                        discoveredUrl = trimmed;
                    }
                    seedQueue.Enqueue(new Seed(ip, defaultSourceType, version, port, 1, trimmed, discoveredUrl));
                }
                await Task.CompletedTask;
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
                logCallback("Processing: " + url);

                try
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
                    BulkCsvLines.Add(csvLine);
                    realTimeBulkCsvCallback?.Invoke(csvLine);

                    if (seed.Depth < maxDepth)
                    {
                        var foundIPs = SeedHelper.ExtractIPAndPort(content);
                        var tasks = new List<Task>();
                        HashSet<string> processedIPSet = new(processedIPs.Keys);
                        foreach (var (ip, port, version) in foundIPs)
                        {
                            if (!processedIPSet.Contains(ip))
                                tasks.Add(ProcessIPAsync(seed, ip, port, version, url, token));
                        }
                        await Task.WhenAll(tasks);
                    }
                }
                catch (Exception ex)
                {
                    logCallback("Error processing " + url + ": " + ex.Message);
                }
            }

            private async Task ProcessIPAsync(Seed seed, string ip, int? port, string version, string discoveredUrl, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();

                if (!scanKnownActive &&
                    (seed.SourceType.Equals("malicious", StringComparison.OrdinalIgnoreCase) ||
                     seed.SourceType.Equals("phishing", StringComparison.OrdinalIgnoreCase) ||
                     seed.SourceType.Equals("DDoS", StringComparison.OrdinalIgnoreCase)))
                {
                    return;
                }

                if (processedIPs.ContainsKey(ip))
                    return;

                string newSourceType = seed.SourceType;
                if (scanKnownActive)
                {
                    bool active = await SeedHelper.IsActiveAndStaticAsync(ip, port ?? 0);
                    if (!active)
                    {
                        if (allowAutoVerdict)
                        {
                            newSourceType = "benign (auto verdict)";
                            string reportDate = DateTime.UtcNow.ToString("o");
                            string comment = $"Auto-WhiteListed benign IP from {seed.OriginalSourceUrl}";
                            string csvLine = $"{ip},\"WhiteList\",{reportDate},\"{EscapeCsvField(comment)}\"";
                            lock (WhiteListCsvLines)
                            {
                                if (WhiteListCsvLines.Count < csvMaxLines + 1)
                                    WhiteListCsvLines.Add(csvLine);
                            }
                            realTimeWhiteListCsvCallback?.Invoke(csvLine);
                            return;
                        }
                    }
                }
                EnqueueSeed(new Seed(ip, newSourceType, version, port ?? 0, seed.Depth + 1, seed.OriginalSourceUrl, discoveredUrl));
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

        #region Scanner and Helper Classes

        public static class SeedHelper
        {
            public static bool IsValidIP(string ip)
            {
                return IPAddress.TryParse(ip, out _);
            }

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

            public static async Task<bool> IsActiveAndStaticAsync(string ip, int? port)
            {
                string url = $"http://{ip}" + (port.HasValue ? $":{port.Value}" : "");
                try
                {
                    using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                    HttpResponseMessage response = await httpClient.GetAsync(url);
                    if (!response.IsSuccessStatusCode)
                        return false;
                    Uri? finalUri = response.RequestMessage?.RequestUri;
                    if (finalUri == null)
                        return false;
                    string finalHostname = finalUri.Host;
                    int finalPort = finalUri.Port > 0 ? finalUri.Port : 80;
                    int expectedPort = port ?? 80;
                    if (!string.IsNullOrEmpty(finalHostname) &&
                        IsValidIP(finalHostname) &&
                        finalHostname == ip &&
                        finalPort == expectedPort)
                    {
                        return true;
                    }
                    return false;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Active/static check failed for {url}: {ex.Message}");
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

        // Filters the log listbox based on the search term entered.
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

        // Event handler for BtnSaveLog Click
        private void BtnSaveLog_Click(object sender, RoutedEventArgs e)
        {
            var sfd = new SaveFileDialog
            {
                Filter = "Text Files|*.txt"
            };

            bool? result = sfd.ShowDialog();

            if (result == true)
            {
                File.WriteAllLines(sfd.FileName, fullLogList);
                MessageBox.Show("Log saved successfully.");
            }
        }

        #endregion

    }
}
