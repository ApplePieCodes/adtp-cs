using ADTP;

namespace TestApp;

class Program
{
    static void Main(string[] args)
    {
        new Thread(ClientThread).Start();
        var listener = new AdtpListener(2025);
        var client = listener.AcceptConnectionSecure();
        var request = client.Recieve();
        Console.WriteLine(request.Build());
    }

    static void ClientThread()
    {
        var client = new AdtpClient();
        client.ConnectSecure("127.0.0.1", 2025);
        client.Send(new RequestBuilder().SetContent("Hello World"));
    }
}