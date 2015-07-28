---
layout: default
title: Evaluation Result 19:4
---
# Evaluation Result 19:4

## Visualization

### Summary

**X-axis**: droidbox log category,  **Y-axis**: log count

<canvas id="SummaryChart" data-type="Line" width="800" height="400" style="width: 800px; height: 400px;"></canvas>

### Tendency

**X-axis**: time (in seconds),  **Y-axis**: log count

<canvas id="TendencyChart" data-type="Line" width="800" height="400" style="width: 800px; height: 400px;"></canvas>


<script src="http://cdn.bootcss.com/jquery/2.1.4/jquery.min.js"></script>
<script src="http://cdn.bootcss.com/Chart.js/1.0.2/Chart.min.js"></script>
<script>
$(document).ready(function(){
    var table_lines = $("tbody").eq(0).children();
    var labels = [];
    var default_data = [];
    var monkey_data = [];
    var random_data = [];
    var static_data = [];
    var dynamic_data = [];

    var show_line_length = 20;
    var line_length = table_lines.length;
    var step = 1
    if (line_length > show_line_length)
	    var step = (line_length/show_line_length)|0;

    for (var i=0; i<table_lines.length; i+=step) {
        line_segs = table_lines.eq(i).children();
        labels.push(line_segs.eq(0).text());
        default_data.push(line_segs.eq(1).text());
        monkey_data.push(line_segs.eq(2).text());
        random_data.push(line_segs.eq(3).text());
        static_data.push(line_segs.eq(4).text());
        dynamic_data.push(line_segs.eq(5).text());
    }
	
    var data = {
        labels: labels,
        datasets: [
            {
                label: "default",
                fillColor: "rgba(255,0,0,0.2)",
                strokeColor: "rgba(255,0,0,1)",
                pointColor: "rgba(255,0,0,1)",
                pointStrokeColor: "#fff",
                pointHighlightFill: "#fff",
                pointHighlightStroke: "rgba(220,220,220,1)",
                data: default_data
            },
            {
                label: "monkey",
                fillColor: "rgba(255,165,0,0.2)",
                strokeColor: "rgba(255,165,0,1)",
                pointColor: "rgba(255,165,0,1)",
                pointStrokeColor: "#fff",
                pointHighlightFill: "#fff",
                pointHighlightStroke: "rgba(220,220,220,1)",
                data: monkey_data
            },
            {
                label: "random",
                fillColor: "rgba(255,255,0,0.2)",
                strokeColor: "rgba(255,255,0,1)",
                pointColor: "rgba(255,255,0,1)",
                pointStrokeColor: "#fff",
                pointHighlightFill: "#fff",
                pointHighlightStroke: "rgba(220,220,220,1)",
                data: random_data
            },
            {
                label: "static",
                fillColor: "rgba(0,255,0,0.2)",
                strokeColor: "rgba(0,255,0,1)",
                pointColor: "rgba(0,255,0,1)",
                pointStrokeColor: "#fff",
                pointHighlightFill: "#fff",
                pointHighlightStroke: "rgba(220,220,220,1)",
                data: static_data
            },
            {
                label: "dynamic",
                fillColor: "rgba(0,0,255,0.2)",
                strokeColor: "rgba(0,0,255,1)",
                pointColor: "rgba(0,0,255,1)",
                pointStrokeColor: "#fff",
                pointHighlightFill: "#fff",
                pointHighlightStroke: "rgba(220,220,220,1)",
                data: dynamic_data
            }
        ]
    };
    var options = {
        multiTooltipTemplate: "<%= datasetLabel %> - <%= value %>",
        pointDot: false,
    };
    var ctx = document.getElementById("SummaryChart").getContext("2d");
    new Chart(ctx).Bar(data, options);


    var table_lines = $("tbody").eq(1).children();
    var labels = [];
    var default_data = [];
    var monkey_data = [];
    var random_data = [];
    var static_data = [];
    var dynamic_data = [];

    var show_line_length = 20;
    var line_length = table_lines.length;
    if (line_length > show_line_length)
	    var step = (line_length/show_line_length)|0;

    for (var i=0; i<table_lines.length; i+=step) {
        line_segs = table_lines.eq(i).children();
        labels.push(line_segs.eq(0).text()+'s');
        default_data.push(line_segs.eq(1).text());
        monkey_data.push(line_segs.eq(2).text());
        random_data.push(line_segs.eq(3).text());
        static_data.push(line_segs.eq(4).text());
        dynamic_data.push(line_segs.eq(5).text());
    }
	
    var data = {
        labels: labels,
        datasets: [
            {
                label: "default",
                fillColor: "rgba(255,0,0,0.2)",
                strokeColor: "rgba(255,0,0,1)",
                pointColor: "rgba(255,0,0,1)",
                pointStrokeColor: "#fff",
                pointHighlightFill: "#fff",
                pointHighlightStroke: "rgba(220,220,220,1)",
                data: default_data
            },
            {
                label: "monkey",
                fillColor: "rgba(255,165,0,0.2)",
                strokeColor: "rgba(255,165,0,1)",
                pointColor: "rgba(255,165,0,1)",
                pointStrokeColor: "#fff",
                pointHighlightFill: "#fff",
                pointHighlightStroke: "rgba(220,220,220,1)",
                data: monkey_data
            },
            {
                label: "random",
                fillColor: "rgba(255,255,0,0.2)",
                strokeColor: "rgba(255,255,0,1)",
                pointColor: "rgba(255,255,0,1)",
                pointStrokeColor: "#fff",
                pointHighlightFill: "#fff",
                pointHighlightStroke: "rgba(220,220,220,1)",
                data: random_data
            },
            {
                label: "static",
                fillColor: "rgba(0,255,0,0.2)",
                strokeColor: "rgba(0,255,0,1)",
                pointColor: "rgba(0,255,0,1)",
                pointStrokeColor: "#fff",
                pointHighlightFill: "#fff",
                pointHighlightStroke: "rgba(220,220,220,1)",
                data: static_data
            },
            {
                label: "dynamic",
                fillColor: "rgba(0,0,255,0.2)",
                strokeColor: "rgba(0,0,255,1)",
                pointColor: "rgba(0,0,255,1)",
                pointStrokeColor: "#fff",
                pointHighlightFill: "#fff",
                pointHighlightStroke: "rgba(220,220,220,1)",
                data: dynamic_data
            }
        ]
    };
    var options = {
        multiTooltipTemplate: "<%= datasetLabel %> - <%= value %>",
        pointDot: false,
    };
    var ctx = document.getElementById("TendencyChart").getContext("2d");
    new Chart(ctx).Line(data, options);
});
</script>

## About

I compare droidbot with droidbox default mode and adb monkey mode. Thus, there are five modes compared:

1. default. (the droidbox default, which just start the app and do nothing)
2. monkey. (adb monkey)
3. random. (droidbot sends events randomly)
4. static. (droidbot sends events according to static analysis)
5. dynamic. (droidbot sends events according to dynamic device states)

In my evaluation, for each mode:

+ droidbox keeps collecting logs for a *duration*;
+ the testing bot (monkey or droidbot) sends events *at intervals* during this time;
+ the number of logs is recorded at each interval.

Comparisons are made between the log counts, and more logs mean higher coverage.

The script `DroidboxEvaluator.py` is what I used to generate the result data.

## Evaluate Strategy:

In this evaluation:

1. DroidboxEvaluator.py took the follow command arguments:
```
apk_path=resources/webviewdemo.apk,
event_duration=100,
event_count=200,
event_inteval=2
```
2. I did NOT restart the emulator before each test;
3. The tested app webviewdemo.apk is a benign app written by myself.

## Findings

DroidBot produce useless noises to DroidBox. The noises are mainly in category `dexclass` and `fdaccess`.
I'm trying to filter these noises out.

## Data

### Summary

|	category	|	1.default	|	2.monkey	|	3.random	|	4.static	|	5.dynamic	|
|----|----|----|----|----|----|
|	closenet	|	0	|	0	|	0	|	0	|	0	|
|	cryptousage	|	0	|	0	|	0	|	0	|	0	|
|	dataleaks	|	0	|	0	|	0	|	0	|	0	|
|	dexclass	|	1	|	2	|	27	|	31	|	18	|
|	fdaccess	|	3	|	7	|	57	|	50	|	113	|
|	opennet	|	0	|	0	|	0	|	0	|	0	|
|	phonecalls	|	0	|	0	|	0	|	0	|	0	|
|	recvnet	|	0	|	0	|	0	|	0	|	0	|
|	sendnet	|	0	|	0	|	0	|	0	|	0	|
|	sendsms	|	0	|	0	|	0	|	0	|	0	|
|	servicestart	|	0	|	0	|	0	|	0	|	8	|
|	sum	|	4	|	9	|	84	|	81	|	139	|

### Tendency

|	time(s)	|	1.default	|	2.monkey	|	3.random	|	4.static	|	5.dynamic	|
|----|----|----|----|----|----|
|	0	|	1	|	2	|	1	|	2	|	14	|
|	5	|	4	|	8	|	8	|	9	|	26	|
|	10	|	4	|	9	|	13	|	10	|	29	|
|	15	|	4	|	9	|	17	|	15	|	33	|
|	20	|	4	|	9	|	22	|	20	|	43	|
|	25	|	4	|	9	|	26	|	25	|	47	|
|	30	|	4	|	9	|	33	|	30	|	54	|
|	35	|	4	|	9	|	38	|	32	|	63	|
|	40	|	4	|	9	|	42	|	33	|	70	|
|	45	|	4	|	9	|	47	|	38	|	77	|
|	50	|	4	|	9	|	48	|	39	|	82	|
|	55	|	4	|	9	|	53	|	44	|	85	|
|	60	|	4	|	9	|	57	|	49	|	93	|
|	65	|	4	|	9	|	60	|	54	|	97	|
|	70	|	4	|	9	|	64	|	57	|	101	|
|	75	|	4	|	9	|	72	|	62	|	108	|
|	80	|	4	|	9	|	76	|	63	|	115	|
|	85	|	4	|	9	|	82	|	68	|	124	|
|	90	|	4	|	9	|	82	|	72	|	128	|
|	95	|	4	|	9	|	82	|	77	|	134	|
|	100	|	4	|	9	|	84	|	81	|	139	|
