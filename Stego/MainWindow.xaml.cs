using Microsoft.Win32;
using Stego.Services;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows;

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

            if(result.GetValueOrDefault(false))
            {
                try
                { 
                    byte[] payload = CryptoService.EncryptMessage(privKeySendTextBox.Text, pubKeySendTextBox.Text, msgTextBox.Text);
                    StegoService.Embed(imageSendTextBox.Text, dialog.FileName, payload);
                    MessageBox.Show("Stego slika uspjesno generisana", "Operacija uspjesna");
                }
                catch(Exception ex)
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
                byte[] payload = StegoService.Extract(stegoImgTextBox.Text);
                msgBox.Text = CryptoService.DecryptMessage(privKeyRecTextBox.Text, pubKeyRecTextBox.Text, payload);
                MessageBox.Show("Stego slika uspjesno dekodovana", "Operacija uspjesna");
            }
            catch(CryptographicException ex)
            {
                MessageBox.Show("Greska prilikom dekriptovanja", "Greska", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch(Exception ex)
            {
                string message = ex.Message;
                message = ex is FileNotFoundException fn ? $"Fajl {Path.GetFileName(fn.FileName)} ne postoji" : message;
                MessageBox.Show(message, "Greska", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void OnPrivateKeySelect(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = GetPemFileDialog();
            bool? result = dialog.ShowDialog();

            if(result.GetValueOrDefault(false))
            {
                privKeySendTextBox.Text = dialog.FileName;
            }
        }
        private void OnPublicKeySelect(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = GetPemFileDialog();
            bool? result = dialog.ShowDialog();

            if (result.GetValueOrDefault(false))
            {
                pubKeySendTextBox.Text = dialog.FileName;
            }
        }

        private void OnImageSelect(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Filter = "PNG|*.png|JPEG|*.jpg;*.jpeg";
            bool? result = dialog.ShowDialog();

            if (result.GetValueOrDefault(false))
            {
                imageSendTextBox.Text = dialog.FileName;
            }
        }

        private void OnPrivateKeyRecSelect(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = GetPemFileDialog();
            bool? result = dialog.ShowDialog();

            if (result.GetValueOrDefault(false))
            {
                privKeyRecTextBox.Text = dialog.FileName;
            }
        }
        private void OnPublicKeyRecSelect(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = GetPemFileDialog();
            bool? result = dialog.ShowDialog();

            if (result.GetValueOrDefault(false))
            {
                pubKeyRecTextBox.Text = dialog.FileName;
            }
        }

        private void OnImageRecSelect(object sender, RoutedEventArgs e)
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
    }
}
