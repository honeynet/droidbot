# DroidBot

## About
A robot which automatically interacts with Android app.

DroidBot sends keyevent, gestures and simulates system events 
in order to exploit more app states automatically.
droidbot decides which actions to take based on static analysis result of app 
and dynamic device information (view hierarchy).

## Introduction
DroidBot mainly does following two things:

1. Setting up device environments, include the contacts, SMS logs, 
call logs, GPS mocking, etc. The target app may have access to these resources, thus we 
prepare them before starting the app.

    Multiple env policies can be used for setting up environments. We support:

    + `none` policy which does not set up any environment;
    + `dummy` policy which just mocks same basic environment for all apps;
    + `static` policy which set up environment according to static information of app,
    for example permissions and files which the app have access to;
    + `file` (to do) policy which read environment configurations from a json file.

2. Sending events during the app is running. Events includes touch, drag gestures on screen, 
keyevents, and simulated broadcasts, etc.

    Similarly, we have several policies to produce events:
    
    + `none` policy which does not send any event;
    + `monkey` policy which make use of adb `monkey` tool, to produce randomized events;
    + `random` policy which sends randomized events to device
    + `static` policy produces a list of events based on static information of app. Eg. 
    the intent-filters of each app.
    + `dynamic` policy. It is actually the real human-like policy. It monitors the device 
    states, including the running activities, the foreground window, and the hierarchy of current 
    window and sends events according to these information.
    It avoids going to same state too many times by comparing the window hierarchies, and 
    it sends activity-specific intents based on static analysis of app.
    + `file` (to do) policy which generates events from a json file.

Moreover, to evaluate whether our bot exploit more app states, I plan to implement a 
Android test coverage tool **which does require repackaging or source code**. 
(note that `Emma` can evaluate coverage with source code)
Android's `traceviewer` is able to record entering and exiting of each method, and we can get a list
of all methods of app via reverse engineering. By comparing `traceviewer` log and app dex, hopefully 
we can get the method coverage of app. The challenge is, `traceviewer` brings too much overhead, because 
it records much information we don't need.

## Prerequisite

1. `Java` version `1.6+`
2. `Python` version `2.7`
3. `Android SDK`, and `platform_tools` and `tools` added to `PATH`
4. (Optional) `DroidBox` version `4.1.1`

## Installation

Clone this repo and cd to the directory.

Run:

```shell
python setup.py install
```

## Usage

1. Start an emulator (recommended) or connect to a device using adb.
2. Start droidbot:
`python droidbot.py -h`

### Usage with Docker

One Example:
```
# Prepare Environment:
$ mkdir -l ~/mobileSamples/out
$ cp mySample.apk ~/mobileSamples/

# Build Docker Container
$ git checkout feature/docker
$ docker build -t honeynet/droidbot:V0.2 .

# Run DroidBot with DroidBox in a Docker Container
$  docker run -it --rm -v ~/mobileSamples:/samples:ro -v ~/mobileSamples/out:/samples/out honeynet/droidbot:V0.2 /samples/mySample.apk
```

## Evaluation

Droidbot is evaluated by comparing with droidbox default mode (which does nothing) 
and adb monkey tool. The results are in [result](/evaluation_reports/README.md).

Or see my visualized evaluation reports at [DroidBot Posts](http://lynnlyc.github.io/droidbot/).

## Acknowledgement

1. [AndroidViewClient](https://github.com/dtmilano/AndroidViewClient) 
is an amazing tool simplifies test script creation providing higher level operations 
and the ability of obtaining the tree of Views present at any given moment on the device 
or emulator screen.
2. [Androguard](http://code.google.com/p/androguard/)
is well-known for reverse-engineering of Android Apks.
