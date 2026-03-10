Release of api builder app.

You need to have Microsoft.PowerShell.SecretStore and Microsoft.PowerShell.SecretManagement then create entries for JWK and your clientID


```
##Powershell
install-module microsoft.powershell.secretstore -Force -Scope CurrentUser
install-module microsoft.powershell.secretmanagement -force -scope currentuser 
register-secretVault -name RSAVault -modulename Microsoft.PowerShell.SecretStore
set-secret -name ClientID -secret "ClientID"
set-secret -name JWK -secret "{JsonJWK Object}"
```
with these objects in place you can then select "Load from store" > get bearer token > and proceed with queries! have fun!

<img width="887" height="791" alt="image" src="https://github.com/user-attachments/assets/0fb7a269-822e-46fc-9c26-f7fc62c5da28" />
<img width="901" height="794" alt="image" src="https://github.com/user-attachments/assets/f88c3b18-78c2-43af-a503-2e8fb9957ef5" />
