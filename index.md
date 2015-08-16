---
layout: default
title: DroidBot by lynnlyc
---

# DroidBot

## Table of Content

+ [Introduction of DroidBot](#introduction)
+ [Installation](#installation)
+ [Usage](#usage)
+ [Comparisons with Monkey](#comparisons-with-monkey)
+ [List of Posts](#list-of-posts)

## Introduction
DroidBot is an Android app exerciser.

It automatically interacts with Android app by sending user events such as gestures, broadcasts and key presses.
It is useful in situations where automatic testing is needed. 
For example, testing Android app in an online sandbox, or testing a large amount of apps.

It does the similar thing as [monkey](http://developer.android.com/tools/help/monkey.html), but is much smarter:

1. DroidBot can get a list of sensitive user events by doing static analysis of Android App;
2. DroidBot can avoid redundant reentries of exploited UI states by dynamic UI analysis.
3. DroidBot does not send random gestures (touch, click etc.) like monkey, instead, 
it send specific gestures according to the position and type of UI element.

DroidBot improves testing coverage by doing static and dynamic analysis of app.
In malware detection, higher coverage often leads to finding more sensitive behaviors.
We integrated DroidBot with [DroidBox](https://github.com/pjlantz/droidbox)
and evaluated DroidBot by comparing with monkey. 
The result demonstrate that DroidBot is better than monkey on detecting more sensitive behaviors.

## Installation



## Usage

## Comparisons with Monkey

## List of Posts

{% for post in site.posts %}
+ [{{ post.title }}]({{ site.baseurl }}{{ post.url }}) {{ post.date | date_to_string }} 
{% endfor %}