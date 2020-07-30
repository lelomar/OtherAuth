# OtherAuth - Joomla Plugin!

Sometimes developers needs to authenticate users to a website from an external database (often from another machine) that is not a Joomla DB.
In order to make this possible and easier, we made this plugin that give the possibility to authenticate from an external DB through the right parameters, in doing so we configure external mySQL connection don't waste so much time to others development process.


## Requirements 

It's relevant that all connection can be established.
Sometimes database are not routed on internet but only inside a VPN or Local Network, so in order to configure all correctly without being crazy first of all check if the database is reachable over the network and if you have all privileges to gain access to MySQL.
After the repository is cloned run check.sh, this scripts will do for you some controls about network and database connections, so make sure the connection is successfully established before proceeding.

## How to Install
It's just a normal plugin, so you want to follow the standard procedure to add a new plugin.
Zip the .php file and the .xml file, and then go to Joomla dashboard: Extension -> Install Extension and after that **enable it**.

## Usage

This plugin has three different approach to authentication:
- Base (Only Users Table)
- M1 (Two Tables Users Table linked to Roles Table)
- MM (Three Tables Users Table linked to Roles Table through Pivot Table)

Despite your selected method there are some configuration that must be done by default.

```
// Connect To DB
DB Driver = MySQL
Host = [IP ADDRESS WHERE DB IS IN LISTENING MODE] 
DB UserName = [ DB USERNAME ] 
DB Password = [ DB PASSWORD ] 
DataBase = [ DB NAME ] 
// Auth Parameters (This is used despite your selected method)
UserTable = [ USER TABLE NAME LIKE "USERS" ]
User Table Name Field = [ NAME FIELD ON USER TABLE NAME LIKE "USERNAME" ]
User Table Email Field = [ EMAIL FIELD NAME LIKE "EMAIL" ] 
User Table Password Field = [ PASSWORD FIELD NAME LIKE "PSWD" ] 
Select an hashing method => [THIS IS A DROPDOWN MENU]
```

If you have selected M1: 
```
User Role For Joomla Access = 
*Foreign Key Role (Primary Key Role) = 
User Role Table Name = 
User Role Field Name = 
*User Role Table Primary Key = 
```
If you selected MM you have this plus all before.
```
Username Field ID (Primary Key User) = 
Joint Table Name (IE Role-User) = 
Joint Table User Primary Key = 
Joint Table Roles Primary Key  = 
```

## How This Plugin is Structured


