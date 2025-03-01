my_ping.py:

Usage: python my_ping.py {destination - hostname or IP} -c {packet count} -i {wait interval} -s {packet size} -t {socket timeout}

my_traceroute.py:

Usage: python my_traceroute.py {destination - hostname or IP} -n -q {num_queries} -S

Not actually working. I started off basing my approach on this Medium article, which seemed to be a common way to implement a UDP packet based traceroute, but I kept having issues with not getting the correct responses back. Since my ICMP ping worked fine, I figured it must have been a UDP issue with my firewall or something similar, but after creating multiple new firewall rules and even disabling it altogether, it still did not work. Through Wireshark, I found that my packets were in fact being sent out, and I was getting an ICMP response with code 11 (time to live exceeded) for all of them. All my UDP packets were also highlighted in red, though I couldn't figure out how to find out what the program meant by that, so I'm still not sure if that was due to the response they got back or an issue with the UDP packets themselves. I've included an example screenshot of this behavior in my report pdf.

After over a day of testing different implementations and looking for any that didn't use UDP protocol (I know the assignment said to use UDP packets for the traceroute, but I just wanted to be sure it woudl work without them), I couldn't find anything suitable, and I had no idea how to do it myself, so I asked an LLM (specifically Deepseek) how it would go about an ICMP only traceroute implementation, and the code it provided worked perfectly, meaning it was in fact an intermediate issue with UDP traffic. Though, obviously, I cannot submit that code.