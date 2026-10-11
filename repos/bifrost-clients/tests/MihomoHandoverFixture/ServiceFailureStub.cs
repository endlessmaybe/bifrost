namespace Bifrost.ClientService;

internal sealed class ServiceFailure : Exception
{
    internal ServiceFailure(string code) : base(code) { }
}
