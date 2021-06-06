using Microsoft.Win32;
using Stego.Services;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;

namespace Stego
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        private void OnCreateMessage(object sender, RoutedEventArgs e)
        {
            SaveFileDialog dialog = new SaveFileDialog();
            dialog.Filter = "PNG|*.png";
            bool? result = dialog.ShowDialog();

            if (result.GetValueOrDefault(false))
            {
                try
                {
                    byte[] payload = CryptoService.EncryptMessage(privKeySendTextBox.Text, pubKeyRecTextBox.Text, msgTextBox.Text);
                    StegoService.Embed(imageSendTextBox.Text, dialog.FileName, payload);
                    MessageBox.Show("Stego slika uspjesno generisana", "Operacija uspjesna");
                }
                catch (Exception ex)
                {
                    string message = ex.Message;

                    message = ex is FileNotFoundException fn ? $"Fajl {Path.GetFileName(fn.FileName)} ne postoji" : message;
                    MessageBox.Show(message, "Greska", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void OnDecryptMessage(object sender, RoutedEventArgs e)
        {

            try
            {
                msgBox.Text = "";
                byte[] payload = StegoService.Extract(stegoImgTextBox.Text);
                (string msg, bool isSignatureValid) = CryptoService.DecryptMessage(privKeyRecTextBox.Text, pubKeySendTextBox.Text, payload);

                if(!isSignatureValid)
                {
                    MessageBox.Show("Neuspjesna verifikacija digitalnog potpisa", "Verifikacija potpisa neuspjesna");
                    return;
                }
                msgBox.Text = msg;
                MessageBox.Show("Stego slika uspjesno dekodovana", "Operacija uspjesna");
            }
            catch (CryptographicException)
            {
                MessageBox.Show("Greska prilikom dekriptovanja", "Greska", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                string message = ex.Message;
                message = ex is FileNotFoundException fn ? $"Fajl {Path.GetFileName(fn.FileName)} ne postoji" : message;
                MessageBox.Show(message, "Greska", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void OnSenderPrivKeyClicked(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = GetPemFileDialog();
            bool? result = dialog.ShowDialog();

            if (result.GetValueOrDefault(false))
            {
                privKeySendTextBox.Text = dialog.FileName;
            }
        }
        private void OnReceiverPubKeyClicked(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = GetPemFileDialog();
            bool? result = dialog.ShowDialog();

            if (result.GetValueOrDefault(false))
            {
                pubKeyRecTextBox.Text = dialog.FileName;
            }
        }

        private void OnSrcImgBttnClicked(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Filter = "PNG|*.png|JPEG|*.jpg;*.jpeg";
            bool? result = dialog.ShowDialog();

            if (result.GetValueOrDefault(false))
            {
                imageSendTextBox.Text = dialog.FileName;
            }
        }

        private void OnReceieverPrivKeyClicked(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = GetPemFileDialog();
            bool? result = dialog.ShowDialog();

            if (result.GetValueOrDefault(false))
            {
                privKeyRecTextBox.Text = dialog.FileName;
            }
        }
        private void OnSenderPubKeyClicked(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = GetPemFileDialog();
            bool? result = dialog.ShowDialog();

            if (result.GetValueOrDefault(false))
            {
                pubKeySendTextBox.Text = dialog.FileName;
            }
        }

        private void OnStegoImgBttnClicked(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Filter = "PNG|*.png";
            bool? result = dialog.ShowDialog();

            if (result.GetValueOrDefault(false))
            {
                stegoImgTextBox.Text = dialog.FileName;
            }
        }

        private OpenFileDialog GetPemFileDialog()
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Filter = "PEM|*.pem";
            return dialog;
        }


        private SaveFileDialog GetPemSaveFileDialog(string title)
        {
            SaveFileDialog dialog = new SaveFileDialog
            {
                Title = title,
                Filter = "PEM|*.pem"
            };
            return dialog;
        }

        private void OnGenerateKeyPair(object sender, RoutedEventArgs e)
        {
            SaveFileDialog privKeyDialog = GetPemSaveFileDialog("Izaberite putanju za privatni ključ");
            SaveFileDialog pubKeyDialog = GetPemSaveFileDialog("Izaberite putanju za javni ključ");

            bool result = privKeyDialog.ShowDialog().GetValueOrDefault(false);

            if (!result)
                return;

            result = pubKeyDialog.ShowDialog().GetValueOrDefault(false);

            if (!result)
                return;

            CryptoService.GenerateRsaKeyPair(privKeyDialog.FileName, pubKeyDialog.FileName);
            MessageBox.Show("Par ključeva uspješno generisan");
        }

        private void OnSenderPrivKeyChanged(object sender, TextChangedEventArgs args)
        {
            ToggleStegoBttnEnabled();
        }

        private void OnReceiverPubKeyChanged(object sender, TextChangedEventArgs args)
        {
            ToggleStegoBttnEnabled();
        }
        private void OnSourceImageChanged(object sender, TextChangedEventArgs args)
        {
            ToggleStegoBttnEnabled();
        }
        private void OnMessageTextChanged(object sender, TextChangedEventArgs args)
        {
            ToggleStegoBttnEnabled();
        }
        private void OnReceiverPrivKeyChanged(object sender, TextChangedEventArgs args)
        {
            ToggleDecrypBttnEnabled();
        }
        private void OnSenderPubKeyChanged(object sender, TextChangedEventArgs args)
        {
            ToggleDecrypBttnEnabled();
        }
        private void OnStegoImgBttnEnabled(object sender, TextChangedEventArgs args)
        {
            ToggleDecrypBttnEnabled();
        }
        private void ToggleStegoBttnEnabled()
            => stegoBttn.IsEnabled = msgTextBox.Text.Length != 0
                && File.Exists(privKeySendTextBox.Text)
                && File.Exists(pubKeyRecTextBox.Text)
                && File.Exists(imageSendTextBox.Text)
                && CryptoService.IsPrivateKeyValid(privKeySendTextBox.Text)
                && CryptoService.IsPublicKeyValid(pubKeyRecTextBox.Text)
                && StegoService.IsValidSourceImageFormat(imageSendTextBox.Text);

        private void ToggleDecrypBttnEnabled()
            => decryptBttn.IsEnabled = File.Exists(privKeyRecTextBox.Text)
                && File.Exists(pubKeySendTextBox.Text)
                && File.Exists(stegoImgTextBox.Text)
                && CryptoService.IsPrivateKeyValid(privKeyRecTextBox.Text)
                && CryptoService.IsPublicKeyValid(pubKeySendTextBox.Text)
                && StegoService.IsValidStegoImageFormat(stegoImgTextBox.Text);
        
    }
}
