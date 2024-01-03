# Trabalho realizado na semana #2

## Identification

- CVE Identifier: CVE-2023-41387.
- Description: This CVE pertains to two vulnerabilities in a popular Flutter package used in iOS apps.
- Relevant Applications/Operating Systems: iOS apps utilizing the vulnerable Flutter package. (flutter_downloader 1.11.1) such as patreon for example.
- Attack complexity: Classified as low.

## Catalogation

- Reporting: The vulnerabilities were discovered and reported by Jan Seredynski.
- Reporting Date: The vulnerabilities were reported on August 25th, 2023.
- Severity Level: The severity of the vulnerabilities is represented by a critical base score of 9.1/10. 
- Bug Bounty: It's not mentioned whether a bug bounty program was in place.

## Exploit

- Allows remote attackers to steal session tokens.
- Also allows attackers to overwrite arbitrary files inside the app's container so that the internal database of the framework is exposed to the local user.
- Exploiting SQL injection.
- Automation: It's not explicitly mentioned whether there are known automated exploits or not.

## Attacks

- Successful Attacks: There is a report made by the person who discovered it, on their own website, of the exploit being used in a, non-disclosed, popular workout IOS app (https://seredynski.com/articles/exploiting-ios-apps-to-extract-session-tokens-and-overwrite-user-data).
- Potential for Damage: The potential for damage includes unauthorized access to user data and manipulation of app functionality.
- Avaiability: This CVE is still avaiable for possible new attacks up to the date of 26/09/2023
