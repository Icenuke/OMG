# --=[ OhMyGenerator ]==--
## Description:
> OhMyGenerator is a python script to generate Logins, Passwords and Email<br>
> This script is based from a wordlist (OhMyWordList.txt) to generate <br>
> The Logins, passwords and Emails are generated on a specific pattern<br>
> It's possible to generate that for a any organization<br>
> All result are exported in files named 'LoginResult.txt', 'PasswordResult.txt' and 'EmailResult.txt'<br>
## How to use:
> 1. Create or modify the file named 'OhMyWordList.txt' with your data
> 2. Usage: OhMyGenerator -l | -p | -m [-e companyName]
> 	1. -l      Generate Login from the Word List.
> 	2. -p      Generate Password from the Word List.
> 	3. -m      Generate Mail from the Word List.
> 	4. -e      Used to generate more password and mail, if is precised in command line, if the name is in many word then add \"\"
## Export files:
> The Export files are construct like:<br>
> Login|Password|Email, Hexadecimal, Base64, URL Encode, MD5, SHA-1, SHA-256