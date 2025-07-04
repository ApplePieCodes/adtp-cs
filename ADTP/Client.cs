using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ADTP;

public class AdtpClient
{
    public bool Secured { get; private set; } = false;
    
    private TcpClient client;
    private NetworkStream stream;
    private byte[] ServerPublicKey;
    private byte[] ClientPublicKey;
    private byte[] ClientPrivateKey;
    private RSA ClientRSA;
    private RSA ServerRSA;
    private AesGcm AesHandler;
    private byte[] AesKey;
    
    public AdtpClient()
    {
        client = new TcpClient();
    }

    public void ConnectSecure(string host, int port)
    {
        client.Connect(host, port);
        stream = client.GetStream();
        
        Send(new RequestBuilder().SetVersion(Version.Adtp2).SetMethod(Method.Read).AddHeader("request-content-type", "text/plain").SetUri("/ADTPS/server-public-key"));
        var response = Recieve();
        ServerPublicKey = Convert.FromBase64String(response.Content);
        
        ClientRSA = RSA.Create(2048);
        ClientPublicKey = ClientRSA.ExportSubjectPublicKeyInfo();
        ClientPrivateKey = ClientRSA.ExportPkcs8PrivateKey();
        
        Send(new RequestBuilder().SetVersion(Version.Adtp2).SetMethod(Method.Create).AddHeader("content-type", "text/plain").SetUri("/ADTPS/client-public-key").SetContent(Convert.ToBase64String(ClientPublicKey)));
        
        response = Recieve();

        while (response.Status != Status.Ok)
        {
            Send(new RequestBuilder().SetVersion(Version.Adtp2).SetMethod(Method.Create).AddHeader("content-type", "text/plain").SetUri("/ADTPS/client-public-key").SetContent(Convert.ToBase64String(ClientPublicKey)));
            response = Recieve();
        }
        
        ServerRSA = RSA.Create();
        ServerRSA.ImportSubjectPublicKeyInfo(ServerPublicKey, out _);
        AesKey = RandomNumberGenerator.GetBytes(32);
        AesHandler = new AesGcm(AesKey);
        
        Send(new RequestBuilder().SetVersion(Version.Adtp2).SetMethod(Method.Create).AddHeader("content-type", "text/plain").SetUri("/ADTPS/aes-key").SetContent(Convert.ToBase64String(ServerRSA.Encrypt(Encoding.UTF8.GetBytes(Convert.ToBase64String(AesKey)), RSAEncryptionPadding.OaepSHA256))));
        
        Secured = true;
    }

    public void ConnectInsecure(string host, int port)
    {
        client.Connect(host, port);
        stream = client.GetStream();
    }

    public void Send(RequestBuilder request)
    {
        if (Secured)
        {
            var nonce = RandomNumberGenerator.GetBytes(12);
            var plaintext = Encoding.UTF8.GetBytes(request.Content);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];
            
            AesHandler.Encrypt(nonce, plaintext, ciphertext, tag);
            request.Content = Convert.ToBase64String(ciphertext);
            request.AddHeader("nonce", Convert.ToBase64String(ServerRSA.Encrypt(nonce, RSAEncryptionPadding.OaepSHA256)));
            request.AddHeader("tag", Convert.ToBase64String(tag));
        }
        
        byte[] data = Encoding.UTF8.GetBytes(request.Build());
        
        stream.Write(data, 0, data.Length);
    }

    public ResponseBuilder Recieve()
    {
        var buffer = new List<byte>();
        var readBuffer = new byte[4096];

        while (true)
        {
            int read = stream.Read(readBuffer, 0, readBuffer.Length);
            if (read == 0)
                throw new IOException("Disconnected before full message received.");

            buffer.AddRange(readBuffer.Take(read));
            string text = Encoding.UTF8.GetString(buffer.ToArray());

            try
            {
                var response = ResponseBuilder.FromString(text);

                if (Secured)
                {
                    var decryptedNonce = ClientRSA.Decrypt(
                        Convert.FromBase64String(response.Headers["nonce"]),
                        RSAEncryptionPadding.OaepSHA256
                    );

                    var tag = Convert.FromBase64String(response.Headers["tag"]);
                    var ciphertext = Convert.FromBase64String(response.Content);
                    var plaintext = new byte[ciphertext.Length];

                    AesHandler.Decrypt(decryptedNonce, ciphertext, tag, plaintext);
                    response.Content = Encoding.UTF8.GetString(plaintext);
                }

                return response;
            }
            catch (JsonException)
            {
                // Not yet a full valid JSON object, continue reading
                continue;
            }
        }
    }
}