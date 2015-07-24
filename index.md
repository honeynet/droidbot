---
layout: default
title: Droidbot by lynnlyc
---

# droidbot

## About
A robot which automatically interacts with app in Droidbox.

droidbot sends keyevent, gestures and simulates system events 
in order to exploit more app states automatically.
droidbot decides which actions to take based on static analysis result of app 
and dynamic device information (view hierarchy).

## Introduction
droidbot mainly does following two things:

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

## List of posts

{% for post in site.posts %}
+ [{{ post.title }}]({{ site.baseurl }}{{ post.url }}) {{ post.date | date_to_string }} 
{% endfor %}