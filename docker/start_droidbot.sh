#!/usr/bin/env bash
python /opt/DroidBot/start.py -d emulator-5554 -a $1 -duration $2 -event dynamic -o /samples/out/ -q -droidbox
