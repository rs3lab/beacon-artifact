call "data/common.gnuplot" "3.0in, 1.2in"
set output "`echo $OUT`"

mp_startx=0.05
mp_starty=0.10
mp_height=0.60
mp_rowgap=0.10
mp_colgap=0.10
mp_width=1.0

eval mpSetup(2, 1)

eval mpNext

set datafile separator ","
set style data histograms
set style fill pattern
# set style fill solid 1.0 border -1
set style histogram gap 0       # Reduce the gap between pillars
set xlabel "Execution time (seconds) ranges"
set ylabel "Percentage"
set title "(a) Distrubtion of execution time"
set xtics rotate by -30
set boxwidth 0.7 absolute
set ytics  40
set yrange [0:100]

plot "data/total-time-1.dat" using 3:xtic(1) title "" lc rgb C6 fillstyle pattern 10, \
     '' using 0:3:(sprintf("%.1f", $3)) with labels offset 0,1 notitle

eval mpNext
