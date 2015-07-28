# Evaluation Result 1

## About

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

## Evaluate Strategy:

In this evaluation:

1. DroidboxEvaluator.py took the follow command arguments:
```
droidbot_home=/Users/yuanchun/project/droidbot,
apk_path=/Users/yuanchun/project/droidbot/resources/webviewdemo.apk,
duration=200,
count=1000,
inteval=2
```
2. Did NOT restart the emulator before each test
3. The tested app webviewdemo.apk is a benign app written by myself

## Findings

According to the result, I found that:

1. It would be better to restart droidbox each time. (to ensure sandboxing.)
2. **IMPORTANT**. droidbox counts accesses to socket/input.jar/am.jar/etc as file accesses,
which are what droidbot uses to generate events.
That is why the droidbot policies generated so many logs.
    We should filter out these useless logs next time.

## Data

|   time	|	default	|	monkey	|	random	|	static	|	dynamic |
|   ----    |   ----    |   ----    |   ----    |   ----    |   ----    |
|   0	|	0	|	0	|	0	|	0	|	0   |
|   2	|	1	|	1	|	1	|	1	|	13	|
|	4	|	2	|	2	|	1	|	2	|	14	|
|	6	|	2	|	4	|	2	|	2	|	14	|
|	8	|	4	|	4	|	4	|	4	|	16	|
|	10	|	4	|	4	|	4	|	4	|	19	|
|	12	|	4	|	4	|	7	|	11	|	18	|
|	14	|	4	|	4	|	10	|	13	|	19	|
|	16	|	4	|	4	|	11	|	14	|	20	|
|	18	|	4	|	4	|	15	|	21	|	21	|
|	20	|	4	|	4	|	16	|	27	|	21	|
|	22	|	4	|	4	|	16	|	27	|	25	|
|	24	|	4	|	4	|	17	|	31	|	33	|
|	26	|	4	|	4	|	19	|	31	|	35	|
|	28	|	4	|	4	|	19	|	37	|	41	|
|	30	|	4	|	4	|	19	|	37	|	42	|
|	32	|	4	|	4	|	21	|	44	|	45	|
|	34	|	4	|	4	|	21	|	47	|	45	|
|	36	|	4	|	4	|	23	|	48	|	45	|
|	38	|	4	|	4	|	23	|	52	|	48	|
|	40	|	4	|	4	|	23	|	52	|	48	|
|	42	|	4	|	4	|	26	|	56	|	52	|
|	44	|	4	|	4	|	29	|	56	|	56	|
|	46	|	4	|	4	|	29	|	59	|	56	|
|	48	|	4	|	4	|	29	|	59	|	63	|
|	50	|	4	|	4	|	29	|	65	|	63	|
|	52	|	4	|	4	|	29	|	65	|	70	|
|	54	|	4	|	4	|	29	|	66	|	70	|
|	56	|	4	|	4	|	29	|	66	|	76	|
|	58	|	4	|	4	|	29	|	67	|	77	|
|	60	|	4	|	4	|	33	|	68	|	80	|
|	62	|	4	|	4	|	34	|	71	|	84	|
|	64	|	4	|	4	|	35	|	72	|	84	|
|	66	|	4	|	4	|	35	|	72	|	90	|
|	68	|	4	|	4	|	39	|	76	|	91	|
|	70	|	4	|	4	|	40	|	76	|	91	|
|	72	|	4	|	4	|	42	|	77	|	97	|
|	74	|	4	|	4	|	42	|	80	|	104	|
|	76	|	4	|	4	|	42	|	85	|	105	|
|	78	|	4	|	4	|	42	|	85	|	108	|
|	80	|	4	|	4	|	42	|	86	|	111	|
|	82	|	4	|	4	|	42	|	89	|	112	|
|	84	|	4	|	4	|	42	|	90	|	115	|
|	86	|	4	|	4	|	42	|	90	|	119	|
|	88	|	4	|	4	|	46	|	91	|	119	|
|	90	|	4	|	4	|	46	|	94	|	122	|
|	92	|	4	|	4	|	50	|	95	|	124	|
|	94	|	4	|	4	|	50	|	99	|	129	|
|	96	|	4	|	4	|	51	|	99	|	132	|
|	98	|	4	|	4	|	51	|	103	|	132	|
|	100	|	4	|	4	|	55	|	104	|	133	|
|	102	|	4	|	4	|	61	|	104	|	136	|
|	104	|	4	|	4	|	64	|	105	|	136	|
|	106	|	4	|	4	|	65	|	109	|	140	|
|	108	|	4	|	4	|	66	|	110	|	141	|
|	110	|	4	|	4	|	66	|	114	|	144	|
|	112	|	4	|	4	|	70	|	114	|	144	|
|	114	|	4	|	4	|	70	|	115	|	145	|
|	116	|	4	|	4	|	71	|	115	|	145	|
|	118	|	4	|	4	|	75	|	119	|	148	|
|	120	|	4	|	4	|	75	|	119	|	148	|
|	122	|	4	|	4	|	79	|	120	|	153	|
|	124	|	4	|	4	|	79	|	121	|	156	|
|	126	|	4	|	4	|	80	|	125	|	156	|
|	128	|	4	|	4	|	81	|	125	|	157	|
|	130	|	4	|	4	|	85	|	126	|	157	|
|	132	|	4	|	4	|	85	|	126	|	160	|
|	134	|	4	|	4	|	89	|	127	|	160	|
|	136	|	4	|	4	|	89	|	128	|	161	|
|	138	|	4	|	4	|	93	|	128	|	164	|
|	140	|	4	|	4	|	93	|	129	|	168	|
|	142	|	4	|	4	|	94	|	129	|	169	|
|	144	|	4	|	4	|	98	|	133	|	172	|
|	146	|	4	|	4	|	98	|	133	|	173	|
|	148	|	4	|	4	|	102	|	137	|	176	|
|	150	|	4	|	4	|	102	|	138	|	176	|
|	152	|	4	|	4	|	106	|	142	|	179	|
|	154	|	4	|	4	|	110	|	142	|	181	|
|	156	|	4	|	4	|	110	|	143	|	184	|
|	158	|	4	|	4	|	111	|	143	|	184	|
|	160	|	4	|	4	|	114	|	147	|	184	|
|	162	|	4	|	4	|	117	|	147	|	185	|
|	164	|	4	|	4	|	118	|	148	|	188	|
|	166	|	4	|	4	|	118	|	149	|	192	|
|	168	|	4	|	4	|	122	|	149	|	193	|
|	170	|	4	|	4	|	122	|	150	|	196	|
|	172	|	4	|	4	|	126	|	151	|	196	|
|	174	|	4	|	4	|	130	|	154	|	197	|
|	176	|	4	|	4	|	130	|	154	|	197	|
|	178	|	4	|	4	|	133	|	155	|	200	|
|	180	|	4	|	4	|	137	|	155	|	200	|
|	182	|	4	|	4	|	138	|	159	|	204	|
|	184	|	4	|	4	|	142	|	159	|	205	|
|	186	|	4	|	4	|	142	|	163	|	208	|
|	188	|	4	|	4	|	143	|	163	|	208	|
|	190	|	4	|	4	|	143	|	164	|	209	|
|	192	|	4	|	4	|	149	|	165	|	212	|
|	194	|	4	|	4	|	152	|	169	|	212	|
|	196	|	4	|	4	|	153	|	170	|	217	|
|	198	|	4	|	4	|	156	|	174	|	220	|
|	200	|	4	|	4	|	157	|	174	|	220 |
