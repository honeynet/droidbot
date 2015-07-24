# Evaluation Results

## About

Here are some preliminary evaluation results of droidbot.

Perhaps the best matrix of performance of a automatic testing bot is the coverage.
However, because we don't have a mature test coverage tool on Android App, 
(in which I mean a test coverage tool that do not need app repackaging.)
we use a alternative approach:

Comparing the number of droidbox logs generated when using different test bots.

We compare droidbot with droidbox default mode (which only start the app) and adb monkey mode.
Thus, there are five modes compared:

1. default. (the droidbox default)
2. monkey. (adb monkey)
3. random. (droidbot sends events randomly)
4. static. (droidbot sends events according to static analysis)
5. dynamic. (droidbot sends events according to dynamic device states)

The script `DroidboxEvaluator.py` is what I use to test and generate results.

## Results

1. [result1](result1.md)