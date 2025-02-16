using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Microsoft.Win32;
using log4net;
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
        // File lists for scanning and WhiteList.
        private readonly List<string> malwareFiles = new();
        private readonly List<string> DDoSFiles = new();
        private readonly List<string> phishingFiles = new();
        private readonly List<string> WhiteListFiles = new();
        private string malwarePath = string.Empty;
        private string ddosPath = string.Empty;
        private string phishingPath = string.Empty;
        private string whiteListPath = string.Empty;

        // Scanner instance – created when the user clicks Start Scan.
        private Scanner? scanner;
        // Cancellation token source to allow stopping the scan.
        CancellationTokenSource? cts;
        // A full log list to support search and saving.
        private readonly List<string> fullLogList = new();

       

        private void Form1_Load(object sender, RoutedEventArgs e)
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

        // Call this method to save current settings to a JSON file.
        // Define the JsonSerializerOptions as a static or class-level field
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

                // Save file lists
                MalwareFiles = malwareFiles,
                DDoSFiles = DDoSFiles,
                PhishingFiles = phishingFiles,
                WhiteListFiles = WhiteListFiles,

                // Save last selected folder and additional folder paths
                MalwarePath = malwarePath,
                DDoSPath = ddosPath,
                PhishingPath = phishingPath,
                WhiteListPath = whiteListPath
            };

            string json = JsonSerializer.Serialize(settings, jsonOptions);
            File.WriteAllText(filePath, json);
        }

        // Call this method to load settings from a JSON file and update the UI.
        private void LoadSettings(string filePath)
        {
            if (File.Exists(filePath))
            {
                string json = File.ReadAllText(filePath);
                AppSettings? settings = JsonSerializer.Deserialize<AppSettings>(json);
                if (settings != null)
                {
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

                    // Restore file lists
                    malwareFiles.Clear();
                    malwareFiles.AddRange(settings.MalwareFiles);
                    DDoSFiles.Clear();
                    DDoSFiles.AddRange(settings.DDoSFiles);
                    phishingFiles.Clear();
                    phishingFiles.AddRange(settings.PhishingFiles);
                    WhiteListFiles.Clear();
                    WhiteListFiles.AddRange(settings.WhiteListFiles);

                    listBoxMalware.Items.Clear();
                    foreach (var item in settings.MalwareFiles)
                    {
                        listBoxMalware.Items.Add(item);
                    }

                    listBoxDDoS.Items.Clear();
                    foreach (var item in settings.DDoSFiles)
                    {
                        listBoxDDoS.Items.Add(item);
                    }

                    listBoxPhishing.Items.Clear();
                    foreach (var item in settings.PhishingFiles)
                    {
                        listBoxPhishing.Items.Add(item);
                    }

                    listBoxWhiteList.Items.Clear();
                    foreach (var item in settings.WhiteListFiles)
                    {
                        listBoxWhiteList.Items.Add(item);
                    }

                    // Restore the last selected folder and additional folder paths
                    malwarePath = settings.MalwarePath;
                    ddosPath = settings.DDoSPath;
                    phishingPath = settings.PhishingPath;
                    whiteListPath = settings.WhiteListPath;
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
            {
                textBoxRealTimeFile.Text = sfd.FileName;
            }
        }

        private void BtnBrowseOutputFile_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog()
            {
                Filter = "CSV Files|*.csv|All Files|*.*",
                Title = "Select Output File"
            };
            if (sfd.ShowDialog() == true)
            {
                textBoxOutputFile.Text = sfd.FileName;
            }
        }

        private void BtnBrowseWhiteListOutputFile_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog()
            {
                Filter = "CSV Files|*.csv|All Files|*.*",
                Title = "Select WhiteList Output File"
            };
            if (sfd.ShowDialog() == true)
            {
                textBoxWhiteListOutputFile.Text = sfd.FileName;
            }
        }

        private void BtnBrowseBulkCsv_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog()
            {
                Filter = "CSV Files|*.csv|All Files|*.*",
                Title = "Select Real-Time Bulk CSV File"
            };
            if (sfd.ShowDialog() == true)
            {
                textBoxRealTimeCsvBulkFile.Text = sfd.FileName;
            }
        }

        private void BtnBrowseWhiteListCsv_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog()
            {
                Filter = "CSV Files|*.csv|All Files|*.*",
                Title = "Select Real-Time WhiteList CSV File"
            };
            if (sfd.ShowDialog() == true)
            {
                textBoxRealTimeCsvWhiteListFile.Text = sfd.FileName;
            }
        }

        // Event handler for the "Save Settings" button.
        private void BtnSaveSettings_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new()
            {
                Filter = "JSON Files|*.json"
            };

          
            if (sfd.ShowDialog() == true)
            {
                SaveSettings(sfd.FileName); 
                MessageBox.Show("Settings saved successfully.");
            }
        }

        // Event handler for the "Load Settings" button.
        private void BtnLoadSettings_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Filter = "JSON Files|*.json"
            };

            bool? result = ofd.ShowDialog();

            if (result == true)
            {
                LoadSettings(ofd.FileName);
                MessageBox.Show("Settings loaded successfully.");
            }
        }

        // Start Scan button clicked.
        private async void BtnStartScan_Click(object sender, RoutedEventArgs e)
        {
            // Read settings from UI controls.
            if (!int.TryParse(textBoxMaxDepth.Text, out int maxDepth))
                maxDepth = 10;
            if (!int.TryParse(textBoxMaxThreads.Text, out int maxThreads))
                maxThreads = 100;
            if (!int.TryParse(textBoxCsvMaxLines.Text, out int csvMaxLines))
                csvMaxLines = 10000;
            if (!int.TryParse(textBoxCsvMaxSize.Text, out int csvMaxSize))
                csvMaxSize = 2097152;

            string outputFileName = textBoxOutputFile.Text;
            string WhiteListOutputFileName = textBoxWhiteListOutputFile.Text;
            string categoryMalicious = textBoxCategoryMalicious.Text;
            string categoryPhishing = textBoxCategoryPhishing.Text;
            string categoryDDoS = textBoxCategoryDDoS.Text;

            cts = new CancellationTokenSource();

            string commentTemplate = textBoxCommentTemplate.Text;

            // Initialize real‑time Bulk CSV file with header if enabled.
            if (checkBoxRealTimeCsvBulk.IsChecked == true && !string.IsNullOrEmpty(textBoxRealTimeCsvBulkFile.Text))
            {
                File.WriteAllText(textBoxRealTimeCsvBulkFile.Text, "IP,Categories,ReportDate,Comment" + Environment.NewLine);
            }
            // Initialize real‑time WhiteList CSV file with header if enabled.
            if (checkBoxRealTimeCsvWhiteList.IsChecked == true && !string.IsNullOrEmpty(textBoxRealTimeCsvWhiteListFile.Text))
            {
                File.WriteAllText(textBoxRealTimeCsvWhiteListFile.Text, "IP,Source,ReportDate,Comment" + Environment.NewLine);
            }

            bool scanKnownActive = checkBoxScanKnownActive.IsChecked.GetValueOrDefault();
            bool allowAutoVerdict = checkBoxAllowAutoVerdict.IsChecked.GetValueOrDefault();
            scanner = new Scanner(
                malwareFiles, DDoSFiles, phishingFiles, WhiteListFiles,
                maxDepth, maxThreads,
                categoryMalicious, categoryPhishing, categoryDDoS,
                csvMaxLines, csvMaxSize,
                outputFileName, WhiteListOutputFileName,
                UpdateLog, UpdateProgress,
                AppendBulkCsvLineToFile, AppendWhiteListCsvLineToFile,
                commentTemplate,
                AddIPv4ToListBox,
                AddIPv6ToListBox,
                allowAutoVerdict);

            await scanner.StartScanAsync(cts.Token);

            // Validate main CSV limits.
            int totalLines = scanner.BulkCsvLines.Count;
            string csvContent = string.Join("\n", scanner.BulkCsvLines);
            int csvSizeInBytes = Encoding.UTF8.GetByteCount(csvContent);

            if (totalLines > csvMaxLines + 1) // +1 for header
            {
                MessageBox.Show("CSV output exceeds the maximum allowed number of lines (" + csvMaxLines + ").");
            }
            else if (csvSizeInBytes > csvMaxSize)
            {
                MessageBox.Show("CSV output exceeds the maximum allowed file size (" + csvMaxSize + " bytes).");
            }
            else
            {
                // Write both CSV outputs.
                File.WriteAllLines(outputFileName, scanner.BulkCsvLines, Encoding.UTF8);
                File.WriteAllLines(WhiteListOutputFileName, scanner.WhiteListCsvLines, Encoding.UTF8);
                MessageBox.Show("Scan completed and CSV files generated successfully.");
            }
        }

        // Stop Scan button clicked.
        private void BtnStopScan_Click(object sender, RoutedEventArgs e)
        {
            if (cts != null)
            {
                cts.Cancel();
                UpdateLog("Scan cancellation requested.");
            }
        }

        // Update IPv4 list box with the .txt file name.
        private void AddIPv4ToListBox(string fileName)
        {
            if (listBoxIPv4.Dispatcher.CheckAccess())
            {
               
                listBoxIPv4.Items.Add(fileName);
            }
            else
            {
                
                listBoxIPv4.Dispatcher.Invoke(new Action(() => listBoxIPv4.Items.Add(fileName)));
            }

        }

        // Update IPv6 list box with the .txt file name.
        private void AddIPv6ToListBox(string fileName)
        {
            if (listBoxIPv6.Dispatcher.CheckAccess())
            {

                listBoxIPv6.Items.Add(fileName);
            }
            else
            {

                listBoxIPv6.Dispatcher.Invoke(new Action(() => listBoxIPv6.Items.Add(fileName)));
            }
          
        }

        // Clear Log button clicked.
        private void BtnClearLog_Click(object sender, RoutedEventArgs e)
        {
            listBoxLog.Items.Clear();
        }

        #region Malware List Handlers

        // "Browse" malware file.
        private void BtnBrowseMalwareFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new()
            {
                Filter = "Text Files|*.txt",
                InitialDirectory = string.IsNullOrEmpty(malwarePath) ? Environment.CurrentDirectory : malwarePath
            };

            bool? result = ofd.ShowDialog();
            if (result == true)
            {
                string filePath = ofd.FileName;
                malwarePath = System.IO.Path.GetDirectoryName(filePath) ?? Environment.CurrentDirectory;
                malwareFiles.Add(filePath);
                listBoxMalware.Items.Add(filePath);
            }
        }

        // "Add" malware file (via text input).
        private void BtnAddMalware_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBoxMalwareInput.Text))
            {
                if (textBoxMalwareInput.Text.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    listBoxMalware.Items.Add(textBoxMalwareInput.Text);
                    malwareFiles.Add(textBoxMalwareInput.Text);
                    textBoxMalwareInput.Clear();
                }
                else
                {
                    MessageBox.Show("File is not a txt file.");
                }
            }
            else
            {
                MessageBox.Show("File does not exist.");
            }
        }

        // "Delete Selected From Malware List" button.
        private void BtnDeleteMalware_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxMalware.SelectedIndex >= 0)
            {
                int index = listBoxMalware.SelectedIndex;
                malwareFiles.RemoveAt(index);
                listBoxMalware.Items.RemoveAt(index);
            }
        }

        #endregion

        #region DDoS List Handlers

        // "Browse" DDoS file.
        private void BtnBrowseDDoSFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new()
            {
                Filter = "Text Files|*.txt",
                InitialDirectory = string.IsNullOrEmpty(ddosPath) ? Environment.CurrentDirectory : ddosPath
            };

            bool? result = ofd.ShowDialog();

            if (result == true)
            {
                string filePath = ofd.FileName;
                ddosPath = System.IO.Path.GetDirectoryName(filePath) ?? Environment.CurrentDirectory;
                DDoSFiles.Add(filePath);
                listBoxDDoS.Items.Add(filePath);
            }
        }

        // "Add" DDoS file (via text input).
        private void BtnAddDDoSFile_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBoxDDoSInput.Text))
            {
                if (textBoxDDoSInput.Text.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    listBoxDDoS.Items.Add(textBoxDDoSInput.Text);
                    DDoSFiles.Add(textBoxDDoSInput.Text);
                    textBoxDDoSInput.Clear();
                }
                else
                {
                    MessageBox.Show("File is not a txt file.");
                }
            }
            else
            {
                MessageBox.Show("File does not exist.");
            }
        }

        // "Delete Selected From DDoS List" button.
        private void BtnDeleteDDoSFile_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxDDoS.SelectedIndex >= 0)
            {
                int index = listBoxDDoS.SelectedIndex;
                DDoSFiles.RemoveAt(index);
                listBoxDDoS.Items.RemoveAt(index);
            }
        }

        #endregion

        #region Phishing List Handlers

        // "Browse" Phishing file.
        private void BtnBrowsePhishingFile_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Filter = "Text Files|*.txt",
                InitialDirectory = string.IsNullOrEmpty(phishingPath) ? Environment.CurrentDirectory : phishingPath
            };

            bool? result = ofd.ShowDialog();

            if (result == true)
            {
                string filePath = ofd.FileName;
                phishingPath = System.IO.Path.GetDirectoryName(filePath) ?? Environment.CurrentDirectory;
                phishingFiles.Add(filePath);
                listBoxPhishing.Items.Add(filePath);
            }
        }

        // "Add" Phishing file (via text input).
        private void BtnAddPhishingFile_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBoxPhishingInput.Text))
            {
                if (textBoxPhishingInput.Text.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    listBoxPhishing.Items.Add(textBoxPhishingInput.Text);
                    phishingFiles.Add(textBoxPhishingInput.Text);
                    textBoxPhishingInput.Clear();
                }
                else
                {
                    MessageBox.Show("File is not a txt file.");
                }
            }
            else
            {
                MessageBox.Show("File does not exist.");
            }
        }

        // "Delete Selected From Phishing List" button.
        private void BtnDeletePhishingFile_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxPhishing.SelectedIndex >= 0)
            {
                int index = listBoxPhishing.SelectedIndex;
                phishingFiles.RemoveAt(index);
                listBoxPhishing.Items.RemoveAt(index);
            }
        }

        #endregion

        #region WhiteList List Handlers

        // "Browse" WhiteList file.
        private void BtnBrowseWhiteListFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new()
            {
                Filter = "Text Files|*.txt",
                InitialDirectory = string.IsNullOrEmpty(whiteListPath) ? Environment.CurrentDirectory : whiteListPath
            };

            bool? result = ofd.ShowDialog();

            if (result == true)
            {
                string filePath = ofd.FileName;
                whiteListPath = System.IO.Path.GetDirectoryName(filePath) ?? Environment.CurrentDirectory;
                WhiteListFiles.Add(filePath);
                listBoxWhiteList.Items.Add(filePath);
            }
        }

        // "Add" WhiteList file (via text input).
        private void BtnAddWhiteList_Click(object sender, RoutedEventArgs e)
        {
            if (File.Exists(textBoxWhiteListInput.Text))
            {
                if (textBoxWhiteListInput.Text.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    listBoxWhiteList.Items.Add(textBoxWhiteListInput.Text);
                    WhiteListFiles.Add(textBoxWhiteListInput.Text);
                    textBoxWhiteListInput.Clear();
                }
                else
                {
                    MessageBox.Show("File is not a txt file.");
                }
            }
            else
            {
                MessageBox.Show("File does not exist.");
            }
        }

        // "Delete Selected From WhiteList" button.
        private void BtnDeleteWhiteList_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxWhiteList.SelectedIndex >= 0)
            {
                int index = listBoxWhiteList.SelectedIndex;
                WhiteListFiles.RemoveAt(index);
                listBoxWhiteList.Items.RemoveAt(index);
            }
        }

        #endregion

        #endregion

        #region UI Helper Methods

        // Thread-safe log updater.
        private bool realtimeLogErrorShown = false;

        private async void UpdateLog(string message)
        {
            string logEntry = $"{DateTime.Now}: {message}";
            fullLogList.Add(logEntry);  // Add the log entry to the fullLogList

          
            if (listBoxLog.Dispatcher.CheckAccess())
            {
            
                listBoxLog.Items.Add(logEntry);
            }
            else
            {
                
                listBoxLog.Dispatcher.Invoke(new Action(() => listBoxLog.Items.Add(logEntry)));
            }

            // Append the log entry to the realtime log file if enabled.
            if (checkBoxRealTimeSave.IsChecked == true && !string.IsNullOrEmpty(textBoxRealTimeFile.Text))
            {
                const int maxRetries = 3;
                int attempt = 0;
                bool success = false;

                while (attempt < maxRetries && !success)
                {
                    try
                    {
                        await File.AppendAllTextAsync(textBoxRealTimeFile.Text, logEntry + Environment.NewLine);
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
                                if (listBoxLog.Dispatcher.CheckAccess())
                                {
                                    // We're on the UI thread
                                    listBoxLog.Items.Add("Error saving realtime log: " + ex.Message);
                                }
                                else
                                {
                                    // We're not on the UI thread, so we need to invoke on the UI thread
                                    listBoxLog.Dispatcher.Invoke(new Action(() => listBoxLog.Items.Add("Error saving realtime log: " + ex.Message)));
                                }
                            }
                        }
                        else
                        {
                            // Wait a short time before trying again.
                            await Task.Delay(100);
                        }
                    }
                }
            }
        }

        // Thread-safe progress updater.
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

        // Real-time appending for Bulk CSV lines.
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
                        MessageBox.Show("Error saving Bulk CSV line: " + ex.Message, "Bulk CSV Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        // Updated AppendWhiteListCsvLineToFile method in Form1 with a locking mechanism:
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

        // Define a simple settings class.
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

            // File lists for scanning
            public List<string> MalwareFiles { get; set; } = new();
            public List<string> DDoSFiles { get; set; } = new();
            public List<string> PhishingFiles { get; set; } = new();
            public List<string> WhiteListFiles { get; set; } = new();

            // New: Additional folder paths for each file type
            public string MalwarePath { get; set; } = string.Empty;
            public string DDoSPath { get; set; } = string.Empty;
            public string PhishingPath { get; set; } = string.Empty;
            public string WhiteListPath { get; set; } = string.Empty;
        }

        /// <summary>
        /// Scanner class:
        /// Loads seeds from files (from three lists), performs HTTP scans concurrently, recursively discovers IPs,
        /// and builds two CSV reports (one for bulk results and one for WhiteListed IPs).
        /// </summary>
        public partial class Scanner
        {
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

            public List<string> BulkCsvLines { get; private set; } = new List<string>();
            public List<string> WhiteListCsvLines { get; private set; } = new List<string>();

            // Concurrent collections for seeds
            private readonly ConcurrentQueue<Seed> seedQueue = new();
            private readonly ConcurrentDictionary<string, bool> processedIPs = new();

            // HashSet to store WhiteListed IPs loaded from WhiteList and blacklist files
            private readonly HashSet<string> WhiteListedIPs = new(StringComparer.OrdinalIgnoreCase);
            private readonly HashSet<string> blacklistIPs = new(StringComparer.OrdinalIgnoreCase);

            int totalSeeds = 0;
            int processedCount = 0;
            private readonly HttpClient httpClient = new();

            private readonly Action<string> realTimeBulkCsvCallback;
            private readonly Action<string> realTimeWhiteListCsvCallback;
            private readonly Action<string> updateIPv4Callback;
            private readonly Action<string> updateIPv6Callback;
            private readonly HashSet<string> filesWithIPv4 = new(StringComparer.OrdinalIgnoreCase);
            private readonly HashSet<string> filesWithIPv6 = new(StringComparer.OrdinalIgnoreCase);
            private readonly object fileLock = new();
            private readonly bool scanKnownActive;
            private readonly bool allowAutoVerdict;

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
                Action<string> updateIPv4Callback,
                Action<string> updateIPv6Callback,
                bool scanKnownActive = false,
                bool allowAutoVerdict = false)
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
                this.updateIPv4Callback = updateIPv4Callback;
                this.updateIPv6Callback = updateIPv6Callback;
                this.scanKnownActive = scanKnownActive;
                this.allowAutoVerdict = allowAutoVerdict;
            }

            private async Task ProcessWhiteListFileAsync(string file, CancellationToken token)
            {
                List<string> WhiteListSites = new();

                // Read the file once.
                using (var reader = new StreamReader(file))
                {
                    string? line;
                    while ((line = await reader.ReadLineAsync(token)) is not null)
                    {
                        token.ThrowIfCancellationRequested();
                        string trimmed = line.Trim();
                        if (string.IsNullOrEmpty(trimmed))
                            continue;

                        // If the line is a valid IP, add it directly.
                        if (IPAddress.TryParse(trimmed, out _))
                        {
                            lock (WhiteListedIPs)
                            {
                                WhiteListedIPs.Add(trimmed);
                            }
                        }
                        else
                        {
                            // Otherwise, treat it as a URL.
                            WhiteListSites.Add(trimmed);
                        }
                    }
                }

                // Process each URL concurrently.
                var tasks = new List<Task>();
                using var semaphore = new SemaphoreSlim(maxThreads); // automatically disposes

                foreach (var url in WhiteListSites)
                {
                    token.ThrowIfCancellationRequested();
                    // Ensure the URL is absolute.
                    string actualUrl = Uri.IsWellFormedUriString(url, UriKind.Absolute) ? url : "http://" + url;
                    await semaphore.WaitAsync(token);
                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            token.ThrowIfCancellationRequested();
                            // Forward the token to GetAsync.
                            var response = await httpClient.GetAsync(actualUrl, token);
                            if (response.IsSuccessStatusCode)
                            {
                                string content = await response.Content.ReadAsStringAsync();
                                var foundIPs = SeedHelper.ExtractIPAndPort(content);
                                foreach (var (ip, port, version) in foundIPs)
                                {
                                    token.ThrowIfCancellationRequested();
                                    // Check if the IP is in the blacklist.
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
                                                {
                                                    WhiteListCsvLines.Add(csvLine);
                                                }
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
                    // Process each WhiteList file.
                    foreach (var file in WhiteListFiles.Where(file => System.IO.Path.GetExtension(file)
                                 .Equals(".txt", StringComparison.OrdinalIgnoreCase)))
                    {
                        await ProcessWhiteListFileAsync(file, token);
                    }

                    // Load seeds from blacklist files.
                    await LoadSeedsFromFileListAsync(malwareFiles, "malicious", token);
                    await LoadSeedsFromFileListAsync(DDoSFiles, "DDoS", token);
                    await LoadSeedsFromFileListAsync(phishingFiles, "phishing", token);

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

            /// <summary>
            /// Loads seeds from each file in the provided list.
            /// If an IP is already WhiteListed, it is recorded in the WhiteList CSV.
            /// Otherwise, a new seed is enqueued for scanning.
            /// </summary>
            [GeneratedRegex(@"^(?<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::(?<port>[0-9]{1,5}))?", RegexOptions.Compiled)]
            private static partial Regex Ipv4Regex();

            [GeneratedRegex(@"^(?<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})(?::(?<port>[0-9]{1,5}))?", RegexOptions.Compiled)]
            private static partial Regex Ipv6Regex();

            private async Task LoadSeedsFromFileListAsync(List<string> fileList, string defaultSourceType, CancellationToken token)
            {
                var ipv4Regex = Ipv4Regex();
                var ipv6Regex = Ipv6Regex();

                foreach (var file in fileList.Where(file => System.IO.Path.GetExtension(file)
                             .Equals(".txt", StringComparison.OrdinalIgnoreCase)))
                {
                    if (token.IsCancellationRequested)
                        return;

                    logCallback($"Loading file: {file}");
                    using (var sr = new StreamReader(file))
                    {
                        string? line;
                        while ((line = await sr.ReadLineAsync(token)) is not null)
                        {
                            if (token.IsCancellationRequested)
                                break;

                            string trimmed = line.Trim();
                            if (string.IsNullOrEmpty(trimmed))
                                continue;

                            // Process each line immediately.
                            Match ipv4Match = ipv4Regex.Match(trimmed);
                            if (ipv4Match.Success)
                            {
                                string ip = ipv4Match.Groups["ip"].Value;
                                // Add to the global blacklist set.
                                blacklistIPs.Add(ip);
                                await ProcessMatch(ipv4Match, "ipv4", file, trimmed, defaultSourceType);
                            }
                            else
                            {
                                Match ipv6Match = ipv6Regex.Match(trimmed);
                                if (ipv6Match.Success)
                                {
                                    string ip = ipv6Match.Groups["ip"].Value;
                                    blacklistIPs.Add(ip);
                                    await ProcessMatch(ipv6Match, "ipv6", file, trimmed, defaultSourceType);
                                }
                            }
                        }
                    }
                    logCallback($"Finished loading file: {file}");
                }
            }
            /// <summary>
            /// Processes a regex match by checking if the IP is already WhiteListed.
            /// If yes, writes to the WhiteList CSV; otherwise, enqueues a new seed for scanning.
            /// </summary>
            private async Task ProcessMatch(Match match, string version, string file, string trimmed, string defaultSourceType)
            {
                string ip = match.Groups["ip"].Value;
                int? port = match.Groups["port"].Success ? (int?)int.Parse(match.Groups["port"].Value) : null;

                // Ensure the IP is processed only once.
                if (!processedIPs.TryAdd(ip, true))
                    return;

                string fileName = System.IO.Path.GetFileName(file);
                if (version.Equals("ipv4", StringComparison.OrdinalIgnoreCase))
                {
                    lock (fileLock)
                    {
                        filesWithIPv4.Add(fileName);  // No need for Contains check
                        updateIPv4Callback?.Invoke(fileName);
                    }
                }
                else if (version.Equals("ipv6", StringComparison.OrdinalIgnoreCase))
                {
                    lock (fileLock)
                    {
                        filesWithIPv6.Add(fileName);  // No need for Contains check
                        updateIPv6Callback?.Invoke(fileName);
                    }
                }

                bool isWhiteListed = WhiteListedIPs.Contains(ip);
                if (isWhiteListed)
                {
                    string reportDate = DateTime.UtcNow.ToString("o");
                    string comment = $"WhiteListed from file: {file}";
                    string csvLine = $"{ip},\"WhiteList\",{reportDate},\"{EscapeCsvField(comment)}\"";
                    lock (WhiteListCsvLines)
                    {
                        if (WhiteListCsvLines.Count < csvMaxLines + 1)
                        {
                            WhiteListCsvLines.Add(csvLine);  // No need for Contains check
                        }
                    }
                    realTimeWhiteListCsvCallback?.Invoke(csvLine);
                }
                else
                {
                    // If scanKnownActive is false, adjust discoveredUrl so that it differs from source URL and file lists.
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

            private void EnqueueSeed(Seed seed)
            {
                if (processedIPs.TryAdd(seed.IP, true))
                {
                    seedQueue.Enqueue(seed);
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
                    {
                        comment = comment[..1024];
                    }
                    string csvLine = $"{seed.IP},\"{category}\",{reportDate},\"{EscapeCsvField(comment)}\"";
                    BulkCsvLines.Add(csvLine);
                    realTimeBulkCsvCallback?.Invoke(csvLine);

                    // When scanning further, pass the current page's URL as the discovered URL for child seeds.
                    if (seed.Depth < maxDepth)
                    {
                        var foundIPs = SeedHelper.ExtractIPAndPort(content);
                        var tasks = new List<Task>();
                        HashSet<string> processedIPSet = new(processedIPs.Keys);
                        foreach (var (ip, port, version) in foundIPs)
                        {
                            if (!processedIPSet.Contains(ip))
                            {
                                tasks.Add(ProcessIPAsync(seed, ip, port, version, url, token));
                            }
                        }
                        await Task.WhenAll(tasks);
                    }
                }
                catch (Exception ex)
                {
                    logCallback("Error processing " + url + ": " + ex.Message);
                }
            }

            /// <summary>
            /// Processes newly discovered IPs on the scanned page.
            /// If scanKnownActive is enabled, checks if the IP is active.
            /// If the check fails, marks it as "benign (auto verdict)", writes to WhiteList CSV, and stores it in memory.
            /// </summary>
            private async Task ProcessIPAsync(Seed seed, string ip, int? port, string version, string discoveredUrl, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();

                // If scanKnownActive is not checked and the seed is from a malicious, phishing, or DDoS source,
                // skip processing further discovered IPs.
                if (!scanKnownActive &&
                    (seed.SourceType.Equals("malicious", StringComparison.OrdinalIgnoreCase) ||
                     seed.SourceType.Equals("phishing", StringComparison.OrdinalIgnoreCase) ||
                     seed.SourceType.Equals("DDoS", StringComparison.OrdinalIgnoreCase)))
                {
                    return;
                }

                // If the IP has already been processed, skip it.
                if (processedIPs.ContainsKey(ip))
                {
                    return;
                }

                string newSourceType = seed.SourceType;
                bool shouldCheckActive = scanKnownActive;
                if (shouldCheckActive)
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
                                {
                                    WhiteListCsvLines.Add(csvLine);
                                }
                            }
                            realTimeWhiteListCsvCallback?.Invoke(csvLine);
                            return;
                        }
                        // If auto verdicts are disabled, continue scanning without auto-WhiteListing.
                    }
                }

                // Enqueue a new seed for further scanning.
                EnqueueSeed(new Seed(ip, newSourceType, version, port ?? 0, seed.Depth + 1, seed.OriginalSourceUrl, discoveredUrl));
            }

            private static string EscapeCsvField(string field)
            {
                return field.Replace("\"", "\\\"");
            }
        }

        /// <summary>
        /// Helper class for IP validation and extraction.
        /// </summary>
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
                // Construct the URL using the given IP and port (if provided)
                string url = $"http://{ip}" + (port.HasValue ? $":{port.Value}" : "");

                try
                {
                    // Create a new HttpClient with a 5-second timeout.
                    using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };

                    // Send the HTTP GET request. HttpClient follows redirects automatically.
                    HttpResponseMessage response = await httpClient.GetAsync(url);

                    // Check if the response status is 200 (OK)
                    if (!response.IsSuccessStatusCode)
                        return false;

                    // Use the null-conditional operator to safely access RequestUri.
                    Uri? finalUri = response.RequestMessage?.RequestUri;
                    if (finalUri == null)
                        return false;

                    string finalHostname = finalUri.Host;
                    // If the final port is not explicitly set, default to port 80.
                    int finalPort = finalUri.Port > 0 ? finalUri.Port : 80;
                    int expectedPort = port ?? 80;

                    // Verify that the final hostname is a valid IP and matches the original IP,
                    // and that the final port matches the expected port.
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
                    // Optionally log the error
                    Console.Error.WriteLine($"Active/static check failed for {url}: {ex.Message}");
                    return false;
                }
            }
        }
        /// <summary>
        /// The Seed class holds data for an individual IP seed.
        /// </summary>
        // 1. Modify the Seed class to hold two URLs:
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


        // Event handler for BtnnSaveLog Click
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