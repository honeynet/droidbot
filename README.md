# DroidBot

## About
A robot which automatically interacts with Android apps.

DroidBot sends keyevent, gestures and simulates system events 
in order to exploit more app states automatically.
DroidBot decides which actions to take based on static analysis result of app
and dynamic device information (view hierarchy).
A 5-min demo can be found [here](https://www.youtube.com/watch?v=3-aHG_SazMY).

For more details, please contact the author [Yuanchun Li](http://sei.pku.edu.cn/~liyc14/) or refer to the [DroidBot blog](http://honeynet.github.io/droidbot/).

## Prerequisite

1. `Python` version `2.7`
2. `Java` version `1.7`
3. `Android SDK`, make sure that `platform_tools` and `tools` added to `PATH`

## Installation

Clone this repo and use pip install:

```shell
git clone https://github.com/honeynet/droidbot.git
pip install -e droidbot
```

If successfully installed, you should be able to execute `droidbot -h`.

## Simple Usage

1. Make sure you have:

    + `.apk` file path of the app you want to analyze.
    + A device or an emulator connected to your host machine via `adb`.
    + Get the serial number of your device/emulator using `adb devices`. For example, the serial number of an emulator is usually `emulator-5554`.

2. Start analyzing:

    ```
    droidbot -d <serial> -a <path_to_apk> -env none -event utg_dynamic
    ```

## env \& event
DroidBot mainly does following two things:

1. Setting up device environments, include the contacts, SMS logs, 
call logs, GPS mocking, etc. The target app may have access to these resources, thus we 
prepare them before starting the app.

    Multiple env policies can be used for setting up environments. We support:

    + `none` policy which does not set up any environment;
    + `dummy` policy which just mocks same basic environment for all apps;
    + `static` policy which set up environment according to static information of app,
    for example permissions and files which the app have access to;
    + `file` policy which read environment configurations from a json file.

2. Sending events during the app is running. Events includes touch, drag gestures on screen, 
keyevents, and simulated broadcasts, etc.

    Similarly, we have several policies to produce events:
    
    + `none` policy does not send any event;
    + `monkey` policy which make use of adb `monkey` tool, to produce randomized events;
    + `random` policy which sends randomized events to device
    + `static` policy produces a list of events based on static information of app. Eg. 
    the intent-filters of each app.
    + `utg_dynamic` policy. It is actually the real human-like policy. It monitors the device 
    states, including the running activities, the foreground window, and the hierarchy of current 
    window and sends events according to these information.
    It avoids going to same state too many times by comparing the window hierarchies, and 
    it sends activity-specific intents based on static analysis of app.
    In older versions of Android where dumping UI hierarchy is slow, try `dynamic` policy.
    + `file` policy which generates events from a json file.

## Scripting

DroidBot supports semi-automatic testing.
Users can write scripts to affect the process of testing.

The script is in json format, which contains three basic objects:

1. `View` selector, which can be used to select a view (aka. a UI component);
2. `State` selector, which can be used to select a state (such as a login Activity);
3. `Operation` object, which defines a set of events to be sent to device (such as screen-touching events).

An example of the DroidBot script is as follows:

```
{
    "views": {
        "login_email": {
            "resource_id": ".*email",
            "class": ".*EditText"
        },
        "login_password": {
            "resource_id": ".*password",
            "class": ".*EditText"
        },
        "login_button": {
            "resource_id": ".*next",
            "class": ".*Button"
        }
    },
    "states": {
        "login_state": {
            "views": ["login_email", "login_password", "login_button"]
        }
    },
    "operations": {
        "login_operation": {
            "operation_type": "custom",
            "events": [
                {
                    "event_type": "text_input",
                    "target_view": "login_email",
                    "text": "ylimit@honeynet.org"
                },
                {
                    "event_type": "text_input",
                    "target_view": "login_password",
                    "text": "ylimitpassword"
                },
                {
                    "event_type": "touch",
                    "target_view": "login_button"
                }
            ]
        }
    },
    "main": {
        "login_state": ["login_operation"]
    },
    "default_policy": "utg_dynamic"
}
```
Explanation of the example:

+ In `views`, we define the view selectors which will be used to select the views we are interested in.
In this example, we define three views which are the email input view, password input view a the login button.
+ In `states`, we define the states in which we want DroidBot to take different operations.
In this example, we define a `login_state` which is a login screen waiting for users to input email and password.
The `login_state` can be recognized by checking the foreground activity name and the view on the screen.
+ In `operations`, we define the operations which will be used in different states.
In this example, we define a `login_operation` which is simply typing email, typing password and press login button.
+ In `main`, we connect the states to corresponding operations.
In this example, we let DroidBot to take `login_operation` in Login state, and use dynamic event policy in other states.

## Use cases

### Usage with DroidBox

Some of you may be interested in using DroidBot with a sandbox in order to do automated taint analysis or malware analysis.

Here is how:

Step 1. Start your sandbox, such as [TaintDroid](http://www.appanalysis.org/) or [DroidBox](https://github.com/pjlantz/droidbox).
Usually setting up a sandbox is not easy, so follow their instructions and be patient.

Step 2. Start DroidBot:
```
droidbot -d <sandbox serial> -a <path to .apk> -event dynamic -o droidbot_out
```

### Usage with Docker

We have a docker image with DroidBot and DroidBox integrated. To use the docker image, follow the steps below:

Prepare the environment on your host by creating a folder to be shared with the **DroidBot** Docker container. The folder will be used to load samples to be analyzed in **DroidBot**, and also to store output results from **DroidBot** analysis.
```
mkdir -p ~/mobileSamples/out
```

Now pull the ready-made Docker container (about 1.8 GB after extraction) from Honeynet Project's hub:
```
docker pull honeynet/droidbot
```

or, if you prefer, build your own from the GitHub repo:
```
git clone https://github.com/honeynet/droidbot.git
docker build -t honeynet/droidbot droidbot
```

To run the analysis, copy your sample to the folder you created above, then start the container; you will find results in the "out" subfolder.
```
cp mySample.apk ~/mobileSamples/
docker run -it --rm -v ~/mobileSamples:/samples:ro -v ~/mobileSamples/out:/samples/out honeynet/droidbot /samples/mySample.apk
ls ~/mobileSamples/out
```

## Evaluation

DroidBot is evaluated by comparing with DroidBot default mode (which does nothing)
and adb Monkey tool. The results are in [result](/evaluation_reports/README.md).

Or see my visualized evaluation reports at [DroidBot Posts](http://honeynet.github.io/droidbot/).

## Acknowledgement

1. [AndroidViewClient](https://github.com/dtmilano/AndroidViewClient) 
is an amazing tool that simplifies test script creation.
2. [Androguard](http://code.google.com/p/androguard/)
is well-known for reverse-engineering of Android APKs.
