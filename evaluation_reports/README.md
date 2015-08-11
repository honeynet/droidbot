# Evaluation Overview

## About

Here are some preliminary evaluation results of droidbot.

The best matrix of performance of automatic testing bots is `test coverage`.
However, because we don't have a mature test coverage tool in Android, 
(which I mean, a test coverage tool that does not need app repackaging.)
we use a alternative approach:

**Comparing the number of droidbox logs generated when using different test bots.**

I compare droidbot with droidbox default mode and adb monkey mode. Thus, there are five modes compared:

1. default. (the droidbox default, which just start the app and do nothing)
2. monkey. (adb monkey)
3. random. (droidbot sends events randomly)
4. static. (droidbot sends events according to static analysis)
5. dynamic. (droidbot sends events according to dynamic device states)

In my evaluation, for each mode:

+ droidbox keeps collecting logs for a *duration*
+ the testing bot (monkey or droidbot) sends event *at intervals* during this time
+ the number of logs is recorded at each time.

Comparisons are made between the log counts, and more logs mean higher coverage.

The script `DroidboxEvaluator.py` is what I used to generate the result data.

## Results

1. [report 1](result1.md)
2. [report 2015-07-28_1904](Evaluation_Report_2015-07-28_1904.md)
3. [report 2015-07-29_2152](Evaluation_Report_2015-07-29_2152.md)
4. [report 2015-07-30_1501](Evaluation_Report_2015-07-30_1501.md)
5. [report 2015-08-09_2146](Evaluation_Report_2015-08-09_2146.md)
6. [report 2015-08-10_0913](Evaluation_Report_2015-08-10_0913.md)
