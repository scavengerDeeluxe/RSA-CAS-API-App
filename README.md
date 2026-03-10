Release of api builder app.

You need to have Microsoft.PowerShell.SecretStore and Microsoft.PowerShell.SecretManagement then create entries for JWK and your clientID

install-module microsoft.powershell.secretstore -Force -Scope CurrentUser install-module microsoft.powershell.secretmanagement -force -scope currentuser register-secretVault -name RSAVault -modulename Microsoft.PowerShell.SecretStore set-secret -name RSA-CAS-ClientId -secret set-secret -name RSA-CAS-JWK -secret

with these objects in place you can then select "Load from store" > get bearer token > and proceed with queries! have fun!
