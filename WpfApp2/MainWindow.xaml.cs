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

            Console.WriteLine(name);

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
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.OpenExistingOnly);

            foreach (X509Certificate2 mCert in store.Certificates)
            {
                //MessageBox.Show(mCert.Subject);
                //certificateStore.DataContext
                if (mCert.HasPrivateKey)
                {
                    try {
                        //RSACryptoServiceProvider privateKey = mCert.PrivateKey as RSACryptoServiceProvider;
                        certificateStore.Items.Add(new X509Certificate2_Wrapper(mCert));
                    }
                    catch {
                        Console.WriteLine("this cert had problems, ", mCert.Subject);
                    }
                }
            }
            store.Close();





        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            // Create OpenFileDialog 
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();



            // Display OpenFileDialog by calling ShowDialog method 
            Nullable<bool> result = dlg.ShowDialog();


            // Get the selected file name and display in a TextBox 
            if (result == true)
            {
                // Open document 
                selectedFile.Content = dlg.FileName;

                if (saveCertificateButton.IsEnabled)
                {
                    saveSignatureButton.IsEnabled = true;
                }


            }
        }

        private void CertificateChanged(object sender, RoutedEventArgs e)
        {
            //MessageBox.Show("changes");
            var certificate = ((X509Certificate2_Wrapper)certificateStore.SelectedItem).certificate;
            var str = certificate.Subject;
            string[] separators1 = {","};
            string[] separators2 = {"="};
            string[] subjectAttributes = str.Split(separators1, StringSplitOptions.RemoveEmptyEntries);

            selectedCertificateCommonName.Content = "";
            selectedCertificateSource_Id.Content = "";
            selectedCertificateSource.Content = "";
            string backupLabel = "";
            string backupValue = "";

            foreach (string elem in subjectAttributes)
            {
                string[] aa = elem.Split(separators2, StringSplitOptions.RemoveEmptyEntries);
                if (aa[0]=="CN")
                {
                    IDLabel.Content = "Common Name:";
                    selectedCertificateCommonName.Content = aa[1];
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
            }

            selectedCertificateIssuer.Content = certificate.Issuer;
            selectedCertificateExpiry.Content = certificate.NotAfter;

            try
            {
                RSACryptoServiceProvider privateKey = certificate.PrivateKey as RSACryptoServiceProvider;
                if (privateKey != null && privateKey.CspKeyContainerInfo != null)
                {
                    if (privateKey.CspKeyContainerInfo.HardwareDevice)
                    {
                        selectedCertificateSource_Id.Content = "Key Source:";
                        selectedCertificateSource.Content = "SmartCard";

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

            private void TextBox_TextChanged(object sender, TextChangedEventArgs e)
        {

        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            var certificate = ((X509Certificate2_Wrapper) certificateStore.SelectedItem).certificate;
            RSACryptoServiceProvider privateKey = certificate.PrivateKey as RSACryptoServiceProvider;
            RSACryptoServiceProvider reconstructedKey = new RSACryptoServiceProvider();
            try
            {
                reconstructedKey.FromXmlString(certificate.PrivateKey.ToXmlString(true));
            }
            catch {
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
                MessageBox.Show("Signed and saved" + filename + ".sign" );
            }
            else {
                MessageBox.Show("Could not sign");
            }


        }
        private void Button_Click_2(object sender, RoutedEventArgs e)
        {


            var certificate = ((X509Certificate2_Wrapper)certificateStore.SelectedItem).certificate;
            string filename = selectedFile.Content.ToString();
            if (filename == "")
            {
                 filename = System.IO.Path.Combine(System.Environment.ExpandEnvironmentVariables("%HOMEDRIVE%%HOMEPATH%"), "Downloads", certificate.SerialNumber);
                //filename = certificate.SerialNumber;
            }


            StringBuilder builder = new StringBuilder();
            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(certificate.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");
            System.IO.File.WriteAllText(filename + ".crt", builder.ToString());
            MessageBox.Show("Saved certificate: "+ filename + ".crt");

        }
    }
}
