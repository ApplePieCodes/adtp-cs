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

public class AdtpListener
{
    private TcpListener listener;
    
    public AdtpListener(int port)
    {
        listener = new TcpListener(port);
        listener.Start();
    }

    public AdtpServerInstance AcceptConnectionSecure()
    {
        return new AdtpServerInstance(listener.AcceptTcpClient(), true);
    }

    public AdtpServerInstance AcceptConnectionInsecure()
    {
        return new AdtpServerInstance(listener.AcceptTcpClient(), false);
    }

    
}

public class AdtpServerInstance
{
    public bool Secured { get; private set; } = false;

    private TcpClient Client;
    private NetworkStream Stream;
    private byte[] ServerPublicKey;
    private byte[] ServerPrivateKey;
    private byte[] ClientPublicKey;
    private RSA ClientRSA;
    private RSA ServerRSA;
    private AesGcm AesHandler;
    private byte[] AesKey;

    internal AdtpServerInstance(TcpClient client, bool secure)
    {
        Client = client;
        Stream = client.GetStream();
        if (secure)
        {
            var request = Recieve();

            ServerRSA = RSA.Create(2048);
            ServerPublicKey = ServerRSA.ExportSubjectPublicKeyInfo();
            ServerPrivateKey = ServerRSA.ExportPkcs8PrivateKey();

            Send(new ResponseBuilder().SetVersion(Version.Adtp2).SetStatus(Status.Ok)
                .AddHeader("content-type", "text/plain").SetContent(Convert.ToBase64String(ServerPublicKey)));

            request = Recieve();

            ClientPublicKey = Convert.FromBase64String(request.Content);

            Send(new ResponseBuilder().SetVersion(Version.Adtp2).SetStatus(Status.Ok));

            request = Recieve();

            AesKey = Convert.FromBase64String(Encoding.UTF8.GetString(ServerRSA.Decrypt(Convert.FromBase64String(request.Content), RSAEncryptionPadding.OaepSHA256)));

            AesHandler = new AesGcm(AesKey);

            Secured = true;
        }
    }

    public void Send(ResponseBuilder request)
    {
        if (Secured)
        {
            var nonce = RandomNumberGenerator.GetBytes(12);
            var plaintext = Encoding.UTF8.GetBytes(request.Content);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];

            AesHandler.Encrypt(nonce, plaintext, ciphertext, tag);
            request.Content = Convert.ToBase64String(ciphertext);
            request.AddHeader("nonce",
                Convert.ToBase64String(ClientRSA.Encrypt(nonce, RSAEncryptionPadding.OaepSHA256)));
            request.AddHeader("tag", Convert.ToBase64String(tag));
        }

        byte[] data = Encoding.UTF8.GetBytes(request.Build());

        Stream.Write(data, 0, data.Length);
    }

    public RequestBuilder Recieve()
    {
        var buffer = new List<byte>();
        var readBuffer = new byte[4096];

        while (true)
        {
            int read = Stream.Read(readBuffer, 0, readBuffer.Length);
            if (read == 0)
                throw new IOException("Client disconnected before full request received.");

            buffer.AddRange(readBuffer.Take(read));
            string text = Encoding.UTF8.GetString(buffer.ToArray());

            try
            {
                var request = RequestBuilder.FromString(text);

                if (Secured)
                {
                    var decryptedNonce = ServerRSA.Decrypt(
                        Convert.FromBase64String(request.Headers["nonce"]),
                        RSAEncryptionPadding.OaepSHA256
                    );

                    var tag = Convert.FromBase64String(request.Headers["tag"]);
                    var ciphertext = Convert.FromBase64String(request.Content);
                    var plaintext = new byte[ciphertext.Length];

                    AesHandler.Decrypt(decryptedNonce, ciphertext, tag, plaintext);
                    request.Content = Encoding.UTF8.GetString(plaintext);
                }

                return request;
            }
            catch (JsonException)
            {
                // Not yet full JSON — keep reading
                continue;
            }
        }
    }
}