@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /link /OUT:implant.exe /SUBSYSTEM:WINDOWS /MACHINE:x64


rem /nologo 	Suppresses display of sign-on banner.
rem /Ox 		A subset of /O2 that doesn't include /GF or /Gy.
	rem /GF 	Enables string pooling.
	rem /Gy 	Enables function-level linking.
	
rem /MT 		Compiles to create a multithreaded executable file, by using LIBCMT.lib.
rem /W0			suppresses all warnings. It's equivalent to /w.
rem /GS 		Checks buffer security. GS- = no buffer security 
rem /DNDEBUG 	Dont compile in debug mode
rem /Tc 		Specified C source file
rem /link		Passes the specified option to LINK.
rem /OUT		specified output file
rem /SUBSYSTEM	specify subsystem, CONSOLE/WINDOWS
rem /MACHINE	specify architecture 
