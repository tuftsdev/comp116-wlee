Assignment 2: The Incident Alarm
Author: Walton Lee

I believe all of the features highlighted in the specification document
were implemented correctly barring the extra credit aspect of reading pcaps.
I collaborated with Danielle Zelin and Skyler Tom.

Hours spent: 9 hours? half of which was getting my way around ruby and
packetFu

Questions:

1. I think the heuristics are definitely not perfect and won't catch every
instance of each scan. However, for catching the most common, basic scans,
the heuristics that I used will suffice.

2. I probably would code it better by having each fingerprint look up being
its own function. Also, if I were to make it a better alarm, I would check
for overlapping cases because I know many shellshock bugs also involve
"shellcode-like" code.
