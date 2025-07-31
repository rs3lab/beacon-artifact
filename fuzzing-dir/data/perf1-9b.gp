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
set ylabel "CPU-core hours (100)"
unset xlabel
set title "(b) Verification time in two settings"
set boxwidth 0.4 absolute
set ytics  5
unset yrange
unset xtics
set key at 0.5,-1

plot "data/sample-impv-1.dat" \
   using ($1/(100000*3600*1000)):xtic(1) title "Optimized" lc rgb C5 fillstyle pattern 9,\
   '' using ($2/(100000*3600*1000)):xtic(1) title "Default" lc rgb C2 fillstyle pattern 7

eval mpNext
