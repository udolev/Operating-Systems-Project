# Operating-Systems-Project
This project was made during an OS course at Lev Academic Center, and is based on Barak Gonen's book - https://data.cyber.org.il/os/os_book.pdf

## Project Summary:
In this project, I developed a software that performs several common stages of malicious activity, centered around code injection techniques. The project involves utilizing Windows API functions for creating hooks, manipulating Import Address Table (IAT), and establishing communication via sockets. The main goal is to demonstrate various stages of a simulated attack, showcasing the capabilities of code injection and remote communication.

Project Steps:

Step A - Implementing IAT Hooking:
I began by executing the exercise outlined in Chapter 9, focusing on Hooking IAT. The program's tasks were as follows:

- Checking for the existence of a "notepad" process.
- Performing IAT Hooking on the "CreateFile" function.
- Displaying a MessageBox with custom text.
  
Step B - Adding DLL Injection: \
To address the challenge of applying Hooking IAT to a different process, I incorporated the techniques from Page 227. Essentially, I executed the Injection DLL exercise, where I developed code to inject a DLL into a separate process, altering its IAT.

Step C - Introducing Remote Reporting: \
In the final stage, I enhanced the project's functionality by implementing remote reporting to a server. The steps were as follows:

Established a socket connection to a server, using the localhost IP address (127.0.0.1) and a chosen port.
Integrated the socket creation within the DLL's WinMain function.
Replaced the previous MessageBox action in the IAT hooking with sending a custom message to the server using the open socket connection.
Throughout the project, I gained an understanding of critical concepts such as IAT hooking, DLL injection, and socket communication. I independently learned the basics of socket programming, drawing from resources like "Computer Networks" documentation provided by the Cyber Education Center and MSDN's documentation for further assistance.
