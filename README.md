# vdetect.cpp
simlulating how anti-virus software work. giving some specific pattern as character of virus


for this program
by default, it will read from the vdetect.str and store all the malicious code.
If -d option was there, then change vdetect.str to the file which is given 
by they user.
the program work in this way:
1.read the files provided by the user, (if no files, read from stdin)
2.read char by char until one line was finish. 
3.reconstruct that line, if there has \xnn, change to one char
4.then scan this line to see if there any malicious code was match
5.continue 2-4 until whe whole file was done (if -s option was there scan)
6.go back to step 1 until no more file to scan 

Note: if read from stdin, any empty line will exit the program, 
      because I consider this is no input for the program.

in this program, I use vector to store the malicious code, 
that is because I don't know how many malicious code was in the vdetect.str. 
Since this is simulate anti-virus function, I need to check 
all the malicious code. Thus I don't want there has a limit to store 
the malicious code information.

this program may not been fully test all the situations, but it seems working
