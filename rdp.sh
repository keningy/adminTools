#!/usr/bin/env bash

REDIRECTED_FLD="/home/user/rdp"

MONITOR_OUTPUT_RE="^([^ ]*).*\b"
MONITOR_SIZE_RE="([0-9]+)x([0-9]+)"
MONITOR_OFFSET_RE="\+([0-9]+)\+([0-9]+)"
MONITOR_OTHER_RE=.*$
MONITOR_RE=$MONITOR_OUTPUT_RE$MONITOR_SIZE_RE$MONITOR_OFFSET_RE$MONITOR_OTHER_RE

## Get window position
WINDOW_POS_X=$(xwininfo -id $(xdotool getactivewindow) |
    grep "Absolute upper-left X" | awk '{print $NF}')
WINDOW_POS_Y=$(xwininfo -id $(xdotool getactivewindow) |
    grep "Absolute upper-left Y" | awk '{print $NF}')

# Loop through each screen and compare the offset with the window
# coordinates.
while read name width height xoff yoff
do
    if [ "$WINDOW_POS_X" -ge "$xoff" \
      -a "$WINDOW_POS_Y" -ge "$yoff" \
      -a "$WINDOW_POS_X" -lt "$(($xoff+$width))" \
      -a "$WINDOW_POS_Y" -lt "$(($yoff+$height))" ]
    then
        RESOLUTION=$width"x"$height
    fi
done < <(xrandr | grep -w connected |
    sed -r "s/$MONITOR_RE/\1 \2 \3 \4 \5/" |
    sort -nk4,5)

# If we found a monitor, echo it out, otherwise print an error.
if [ ! -z "$RESOLUTION" ]
then
    echo $RESOLUTION
else
    echo "Couldn't find any monitor for the current window." >&2
    exit 1
fi

XFREERDP_ST_OPT="/sec:tls /smartcard:"" /size:$RESOLUTION +fonts /drive:rdp,$REDIRECTED_FLD /v:$1"
echo $XFREERDP_ST_OPT

xfreerdp $XFREERDP_ST_OPT
