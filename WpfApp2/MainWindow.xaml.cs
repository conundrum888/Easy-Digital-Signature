using System;
using System.Text;
using System.Windows;
using System.Security.Cryptography;
using System.Windows.Controls;
using System.Security.Cryptography.X509Certificates;

namespace WpfApp2
{

    public class X509Certificate2_Wrapper
    {
        public string name;
        public X509Certificate2 certificate;

        public X509Certificate2_Wrapper(X509Certificate2 obj)
        {
            certificate = obj;
            var str = certificate.Subject;
            string[] separators1 = { "," };
            string[] subjectAttributes = str.Split(separators1, StringSplitOptions.RemoveEmptyEntries);
            var backupName = "";
            name = "";
            foreach (string elem in subjectAttributes)
            {
                if (backupName == "")
                {
                    backupName = elem;
                }
                if (elem.StartsWith("CN="))
                {
                    name = elem;
                }
            }
            if (name == "")
            {
                name = backupName;
            }
        }

        public override string ToString()
        {
            return name+" (Expires: "+certificate.NotAfter+")";
        }


    }
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            try {
                X509Store userStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                X509Store machineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                userStore.Open(OpenFlags.OpenExistingOnly);
                machineStore.Open(OpenFlags.OpenExistingOnly);

                foreach (X509Certificate2 mCert in userStore.Certificates)
                {
                    if (mCert.HasPrivateKey)
                    {
                        try
                        {
                            certificateStore.Items.Add(new X509Certificate2_Wrapper(mCert));
                        }
                        catch
                        {
                        }
                    }
                }
                foreach (X509Certificate2 mCert in machineStore.Certificates)
                {
                    if (mCert.HasPrivateKey)
                    {
                        try
                        {
                            certificateStore.Items.Add(new X509Certificate2_Wrapper(mCert));
                        }
                        catch
                        {
                        }
                    }
                }

                userStore.Close();
                machineStore.Close();
            }
            catch {
                MessageBox.Show("Could not access the certificate store");
            }
        }

        private void chooseFile(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();
            Nullable<bool> result = dlg.ShowDialog();
            if (result == true)
            {
                selectedFile.Content = dlg.FileName;

                if (saveCertificateButton.IsEnabled)
                {
                    saveSignatureButton.IsEnabled = true;
                }

            }
        }

        private void CertificateChanged(object sender, RoutedEventArgs e)
        {
            var certificate = ((X509Certificate2_Wrapper)certificateStore.SelectedItem).certificate;
            var str = certificate.Subject;
            string[] separators1 = {","};
            string[] separators2 = {"="};
            string[] subjectAttributes = str.Split(separators1, StringSplitOptions.RemoveEmptyEntries);

            selectedCertificateCommonName.Content = "";
            selectedCertificateExt1_Id.Content = "";
            selectedCertificateExt1.Content = "";
            selectedCertificateExt2_Id.Content = "";
            selectedCertificateExt2.Content = "";
            selectedCertificateCommonName.ToolTip = null;
            selectedCertificateExt1_Id.ToolTip = null;
            selectedCertificateExt1.ToolTip = null;
            selectedCertificateExt2_Id.ToolTip = null;
            selectedCertificateExt2.ToolTip = null;



            string backupLabel = "";
            string backupValue = "";
            foreach (string elem in subjectAttributes)
            {
                string[] aa = elem.Split(separators2, StringSplitOptions.RemoveEmptyEntries);
                if (aa[0]!=null && aa[0]=="CN")
                {
                    IDLabel.Content = "Common Name:";
                    selectedCertificateCommonName.Content = aa[1];
                    selectedCertificateCommonName.ToolTip = aa[1];
                }
                if (backupValue == "")
                {
                    backupLabel = aa[0];
                    backupValue = aa[1];
                }

            }
            if (selectedCertificateCommonName.Content.ToString() == "")
            {
                IDLabel.Content = backupLabel=="E"?"Email:": backupLabel + ":";
                selectedCertificateCommonName.Content = backupValue;
                selectedCertificateCommonName.ToolTip = backupValue;

            }

            selectedCertificateIssuer.Content = certificate.Issuer;
            selectedCertificateIssuer.ToolTip = certificate.Issuer;
            selectedCertificateIssuer_Id.Content = "Issuer:";
            
            selectedCertificateExpiry.Content = certificate.NotAfter;
            selectedCertificateExpiry_Id.Content = "Expiry:";
            try
            {
                RSACryptoServiceProvider privateKey = certificate.PrivateKey as RSACryptoServiceProvider;
                if (privateKey != null && privateKey.CspKeyContainerInfo != null)
                {
                    if (privateKey.CspKeyContainerInfo.HardwareDevice)
                    {
                        selectedCertificateExt1_Id.Content = "Key Source:";
                        selectedCertificateExt1.Content = "SmartCard";
                        selectedCertificateExt1.ToolTip = "SmartCard";

                    }
                }

            }
            catch
            {

            }
            try
            {
                foreach (X509Extension extension in certificate.Extensions)
                {
                    if (extension.Oid.FriendlyName == "Key Usage")
                    {
                        X509KeyUsageExtension ext = (X509KeyUsageExtension)extension;
                        //MessageBox.Show(certificate.Subject+": "+ext.KeyUsages.ToString());
                        //Console.WriteLine(ext.KeyUsages);
                        if ((string)selectedCertificateExt1.Content!="") {
                            selectedCertificateExt2_Id.Content = "Key Usages:";
                            selectedCertificateExt2.Content = ext.KeyUsages.ToString();
                            selectedCertificateExt2.ToolTip = ext.KeyUsages.ToString();

                        }
                        else
                        {
                            selectedCertificateExt1_Id.Content = "Key Usages:";
                            selectedCertificateExt1.Content = ext.KeyUsages.ToString();
                            selectedCertificateExt1.ToolTip = ext.KeyUsages.ToString();
                        }
                    }
                }
            }
            catch
            {

            }

            saveCertificateButton.IsEnabled = true;
            if (selectedFile.Content!=null && selectedFile.Content.ToString()!="")
            {
                saveSignatureButton.IsEnabled = true;
            }
        }

        private void saveSignature(object sender, RoutedEventArgs e)
        {
            try
            {
                var certificate = ((X509Certificate2_Wrapper)certificateStore.SelectedItem).certificate;
                RSACryptoServiceProvider privateKey = certificate.PrivateKey as RSACryptoServiceProvider;
                RSACryptoServiceProvider reconstructedKey = new RSACryptoServiceProvider();
                try
                {
                    reconstructedKey.FromXmlString(certificate.PrivateKey.ToXmlString(true));
                }
                catch
                {
                    reconstructedKey = privateKey;
                }
                RSACryptoServiceProvider publicKey = certificate.PublicKey.Key as RSACryptoServiceProvider;
                var filename = selectedFile.Content.ToString();
                byte[] buffer = System.IO.File.ReadAllBytes(filename);
                byte[] signature = reconstructedKey.SignData(buffer, CryptoConfig.MapNameToOID("SHA256"));
                bool verify = publicKey.VerifyData(buffer, CryptoConfig.MapNameToOID("SHA256"), signature);
                if (verify)
                {
                    System.IO.File.WriteAllBytes(filename + ".sign", signature);
                    MessageBox.Show("Signed and saved" + filename + ".sign");
                }
                else
                {
                    MessageBox.Show("Signature failed");
                }
            }
            catch
            {
                MessageBox.Show("Signature failed");
            }

        }
        private void saveCertificate(object sender, RoutedEventArgs e)
        {
            try
            {
                var certificate = ((X509Certificate2_Wrapper)certificateStore.SelectedItem).certificate;
                string filename = selectedFile.Content.ToString();
                if (filename == "")
                {
                    filename = System.IO.Path.Combine(System.Environment.ExpandEnvironmentVariables("%HOMEDRIVE%%HOMEPATH%"), "Downloads", "certificate");
                }

                StringBuilder builder = new StringBuilder();
                builder.AppendLine("-----BEGIN CERTIFICATE-----");
                builder.AppendLine(Convert.ToBase64String(certificate.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine("-----END CERTIFICATE-----");
                System.IO.File.WriteAllText(filename + ".crt", builder.ToString());
                MessageBox.Show("Saved certificate: " + filename + ".crt");
            }
            catch 
            {
                MessageBox.Show("Certificate could not be saved");
            }

            
        }
    }
}
