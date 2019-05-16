import os
import sys
import subprocess as sub
import tempfile
temp = tempfile.NamedTemporaryFile(mode='a+b', suffix=".txt", delete=False)
try:
    with open(sys.argv[2], 'rU') as fp:
        print 'opened'
        for line in fp:
            temp.write(line)
    temp.seek(0)
    cmd = 'LogParser.exe file:'+sys.argv[1]+'?FIleName="'+sys.argv[2]+'"+destinationDirectory="'+sys.argv[3]+'"+sourceFile="'+temp.name+'" -stats:OFF -i:TSV -nSkipLines:1 -headerRow:off -fixedSep:ON -nFields:39 -filemode:0 -q'
    print cmd
    p = sub.Popen(cmd, stdin=sub.PIPE, stdout=sub.PIPE, stderr=sub.STDOUT)
    p.wait()
    print p.stdout.read()
    temp.close()
    os.unlink(temp.name)
except Exception as e:
    print e