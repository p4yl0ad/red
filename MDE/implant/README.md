# PSEUDOCODE 

WINDOWS (GUITRICK) window main function
  allocates READWRITE memory the size of the calc_payload
  Decrypts shellcode 
  Moves now decrypted payload into the READWRITE memory buffer
  Changes memory protections on buffer to RX 
  
  Searches for target processID
  if finds processID then open process to get a handle to the process
  
  Injects into processhandle with the memory buffer 
  closes handle
  returns 0
