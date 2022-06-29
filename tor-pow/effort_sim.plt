set object 1 rect from 1000,graph 0 to 6000,graph 1 fc rgb 'gray'
set object 2 rect from 10000,graph 0 to 16000,graph 1 fc rgb 'gray'
set object 3 rect from 20000,graph 0 to 26000,graph 1 fc rgb 'gray'
set ytics nomirror
set y2tics
set xlabel 'time [s]'
set title 'Effort estimation v1, min=5000, small botnet'
set ylabel 'Suggested effort' tc 'dark-violet'
set ytics tc 'dark-violet'
set y2label 'Queue size' tc 'sea-green'
set y2tics tc 'sea-green'
plot 'strat_AIMD.dat' u 1:2 notitle lc 'dark-violet', 'strat_AIMD.dat' u 1:3 axes x1y2 notitle lc 'sea-green'
#set datafile missing "?"
#set ylabel 'Time to connect [s]' tc 'dark-red'
#set ytics tc 'dark-red'
#set y2label 'Client conn. per sec.' tc 'blue'
#set y2tics tc 'blue'
#plot 'strat3.dat' u 1:($5) notitle lc 'dark-red', 'strat3.dat' u 1:4 axes x1y2 notitle lc 'blue'
