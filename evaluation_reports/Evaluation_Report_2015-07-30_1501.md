# Evaluation_Report_2015-07-30_1501

## About

This report is generated automatically by DroidboxEvaluator with options:

+ apk_path=malware2.apk
+ event_duration=300
+ event_interval=2
+ event_count=2

In this test, the app showed an dialogue and asked for Device Administrator privilege. 
Only DroidBot with `dynamic` event policy stepped over the case.
Thus the log count of dynamic mode is significantly larger.

## Apk Info

|Item|Value|
|----|----|
|Package Name|com.gnom.anton|
|Main Activity|com.gnom.anton.Short|
|Hash (md5)|f56079b95e34a175d880524b1b531272|
|Hash (sha1)|2fed6dd974a6a6f26213f4b5d047081bbb8974ae|
|Hash (sha256)|002419b9823810ed04ebb0d3b1c3c8b1e296e0ab0526c384183f1423eab0cf77|

### Permissions

+ android.permission.INTERNET
+ android.permission.ACCESS_NETWORK_STATE
+ android.permission.READ_PHONE_STATE
+ android.permission.RECEIVE_BOOT_COMPLETED
+ android.permission.WAKE_LOCK
+ android.permission.WRITE_EXTERNAL_STORAGE
+ android.permission.READ_EXTERNAL_STORAGE
+ android.permission.SYSTEM_ALERT_WINDOW
+ android.permission.CAMERA
+ android.permission.READ_CONTACTS
+ android.permission.GET_TASKS
+ android.permission.WRITE_SETTINGS

## Data

### Summary

|	category	|	1.default	|	2.monkey	|	3.random	|	4.static	|	5.dynamic	|
|----|----|----|----|----|----|
|	closenet	|	0	|	0	|	0	|	0	|	0	|
|	cryptousage	|	0	|	0	|	0	|	0	|	0	|
|	dataleaks	|	6	|	7	|	5	|	6	|	20	|
|	dexclass	|	2	|	2	|	5	|	7	|	9	|
|	fdaccess	|	10	|	12	|	33	|	32	|	34	|
|	opennet	|	5	|	6	|	4	|	5	|	18	|
|	phonecalls	|	0	|	0	|	0	|	0	|	0	|
|	recvnet	|	10	|	12	|	8	|	10	|	36	|
|	sendnet	|	5	|	6	|	4	|	5	|	18	|
|	sendsms	|	0	|	0	|	0	|	0	|	0	|
|	servicestart	|	1	|	2	|	26	|	11	|	94	|
|	sum	|	39	|	47	|	85	|	76	|	229	|

### Tendency

|	time	|	1.default	|	2.monkey	|	3.random	|	4.static	|	5.dynamic	|
|----|----|----|----|----|----|
|	0	|	0	|	1	|	1	|	1	|	1	|
|	15	|	19	|	27	|	28	|	14	|	12	|
|	30	|	19	|	27	|	30	|	14	|	12	|
|	45	|	19	|	27	|	31	|	16	|	16	|
|	60	|	19	|	27	|	31	|	16	|	16	|
|	75	|	24	|	32	|	38	|	16	|	16	|
|	90	|	24	|	32	|	48	|	23	|	16	|
|	105	|	24	|	32	|	50	|	23	|	16	|
|	120	|	24	|	32	|	50	|	23	|	58	|
|	135	|	29	|	37	|	50	|	23	|	143	|
|	150	|	29	|	37	|	50	|	29	|	214	|
|	165	|	29	|	37	|	50	|	30	|	228	|
|	180	|	29	|	37	|	50	|	30	|	229	|
|	195	|	34	|	42	|	52	|	30	|	229	|
|	210	|	34	|	42	|	56	|	46	|	229	|
|	225	|	34	|	42	|	56	|	76	|	229	|
|	240	|	34	|	42	|	56	|	76	|	229	|
|	255	|	39	|	47	|	83	|	76	|	229	|
|	270	|	39	|	47	|	85	|	76	|	229	|
|	285	|	39	|	47	|	85	|	76	|	229	|
|	300	|	39	|	47	|	85	|	76	|	229	|
