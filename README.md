# DG_Readiness_Tool
The idea behind this is to split the original script into a Get / Set scripts and clean up the code.
The original script came to me as "DG_Readiness_Tool_v3.6".  I will continue to use it for notes.


Issues:
* Script contains some documentation for the operation of it, but not how the script works 
*** Update and add documentation 
* Script both tests and modifies
 ** Split these two function out to a Get-DG_Readiness and a Set-DG_Readiness 
* Script is very messy and hard to read 
** Clean up the code and modernize it 
* Script is slow. It performs work, just to do it 
** Remove unneeded code. 
* Functions do not use standard verbs 
** Standardize verbs. 
* Functions contain inline parameters 
** Modernize functions 
*  








