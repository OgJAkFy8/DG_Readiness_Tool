# DG Readiness Tool
The idea behind this is to split the original script into a Get / Set scripts and clean up the code.
The original script came to me as "DG_Readiness_Tool_v3.6".  I will continue to use it for notes.

## Issues:
* Script contains some documentation for the operation of it, but not how the script works 
  * Update and add documentation 
  * Modernize the documentation, by putting it into a Comment-Based help
* The original script both tests and modifies.  
  * This could cause the user to make unexpected changes to the system.
  * Split these two functions out to a Get-DG_Readiness and a Set-DG_Readiness 
* Script is very messy and hard to read 
  * Clean up the code and modernize it 
* Script is slow. It performs work, just to do it 
  * Remove unneeded code 

## Other repairs to be made
* Functions do not use standard verbs 
* Avoid Write-Host
* Double-quoted string has no expandable content
* Functions use inline parameters
* Parameters have not defined type
* Use -f operator
* Redundant String Content
* CmdletBinding() Missing
* Public functions uses no Verb-Noun name
* Application path unqualified
* Redundant String Content
* Application has no extension
* Use environmental variables in path
* Semicolon instead of line break
* Missing comment-based help
* Unapproved Verb in Function Name
  * Standardize verbs ` Get-Verb `








