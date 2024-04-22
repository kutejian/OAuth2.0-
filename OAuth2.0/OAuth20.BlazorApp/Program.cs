using Microsoft.EntityFrameworkCore;
using OAuth20.BlazorApp.Data;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Exceptions;

// TODO: remove OAuth20.Example
// TODO: Add Credentials 

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddSingleton<WeatherForecastService>();

builder.Services.AddDbContext<AppDbContext>(opt => opt.UseInMemoryDatabase("InMemoryDb"));

var serilogLogger = new LoggerConfiguration()
    .Enrich.WithProperty("Oid", Guid.NewGuid().ToString())
    .Enrich.With(new OperationIdEnricher())
    .Enrich.FromLogContext()
    .Enrich.WithExceptionDetails()
    .ReadFrom.Configuration(builder.Configuration)
    .CreateLogger();

builder.Services.AddLogging(logging =>
{
    logging.ClearProviders();
    logging.AddSerilog(serilogLogger, true);
    if (builder.Environment.IsDevelopment())
    {
        logging.AddConsole();
    }
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");

    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();

public class OperationIdEnricher : ILogEventEnricher
{
    public void Enrich (LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        if (!logEvent.Properties.ContainsKey("Rid"))
        {
            var operationProperty = propertyFactory.CreateProperty("Rid", Guid.NewGuid().ToString());
            logEvent.AddPropertyIfAbsent(operationProperty);
        }
    }
}