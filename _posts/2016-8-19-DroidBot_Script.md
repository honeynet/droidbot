---
layout: default
title: Using scripts to guide online Android app analysis
---

# Using scripts to guide online Android app analysis

When analyzing Android app in an online sandbox, we often need an automated test input generation tool (such as Monkey or DroidBot) to produce some test inputs. However, test input generation tools often feel hard to pass some special situations such as login, first-use guide and unlock screens, where human's knowledge is needed.

We propose a scripting machanism in DroidBot to support user-guided testing. Based on the machanism, users are able to customize the operations for DroidBot to take in certain states. For example, [K-9 Mail](https://play.google.com/store/apps/details?id=com.fsck.k9) requires login to continue, and most existing test input generation tools would stuck at the login screen when testing it. However, with DroidBot script, users would be able to help DroidBot pass the login screen of their apps by scripting the login operation: *Input email, input password and click "Next"*.

<video controls width="100%">
  <source src="{{site.baseurl}}/static/droidbot_script.mp4" type="video/mp4">
  <source src="{{site.baseurl}}/static/droidbot_script.webm" type="video/webm">
Your browser does not support the video tag.
</video>

Let's clarify some basic concepts that are important in DroidBot script:

+ **View** is a UI component which can be interacted with (`Button`, `Menu`, etc.) or be used to render some content (`ImageView`, `TextView`, etc.);
+ **State** is a snapshot of app which represents a special situation, such as where the app is waiting for login input. A **state** could be identified based on the foreground activity, background services and the **view**s on the screen;
+ **Event** is what DroidBot sends to device, including gestures and intents. Gesture events often have a target **view**, for example clicking the "Next" button;
+ **Operation** is a combination of events. Usually an **operation** is is used to pass a **state**.

As DroidBot is based on the *UI state transition graph* of an app, the scripting language provided by DroidBot is also state-based. To write a script for DroidBot, you will have to:

1. Find out the **state**s you want to deal with, and figure out how to identify the **state**s;
2. Think about the **operation**s to take in each **state** and serialize the **operation**s with **event**s.

Then you can start to write a DroidBot script. The script is in `json` format. The brevity and clear structure of `json` are perfectly fit to depict the above concepts, and also `json` is familiar to most developers. 

In the K9 Mail example, the state we want to deal with is the login screen, which contains a email input field, and password input field and a Next button. Let's name the state as `login_state` and the three views as `login_email`, `login_password` and `login_button` repectively. In order to identify a state, we have to define a state selector. The definition of `login_state` selector could be:

{% highlight json %}
"login_state": {
    "views": ["login_email", "login_password", "login_button"]
}
{% endhighlight %}

which means, when `login_email` view, `login_password` view and `login_button` view are in current state, the state would be identified as `login_state`.

In order to identify the three views, we also need to define three view selectors. We can use `uiautomatorviewer` to find out how to identify a view.

<img width="100%" src="{{site.baseurl}}/static/uiautomatorviewer.png" />

For the email input field, the resource-id is `com.fsck.k9:id/account_email` and the class is `android.widget.EditText`, thus we can use regular expression `.*email` to match the resource-id and `.*EditText` to match the class name. The definitions of the three view selectors are as follows:

{% highlight json %}
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
{% endhighlight %}

Here we are able to identify `login_state`. We know that the operation to take in `login_state` is "input email, input password and click Next", which can be represented as three gesture events in DroidBot:

{% highlight json %}
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
            "text": "ylimit_password"
        },
        {
            "event_type": "touch",
            "target_view": "login_button"
        }
    ]
}
{% endhighlight %}

Finally, we tell DroidBot to take `login_operation` in `login_state`:

{% highlight json %}
"main": {
    "login_state": ["login_operation"]
}
{% endhighlight %}

So far we have finished a simple script to help DroidBot pass the login screen.
The source version is available [here](https://github.com/honeynet/droidbot/blob/master/script_samples/pass_login_script.json).

For more details about DroidBot script and more features of DroidBot please refer to its [github page](https://github.com/honeynet/droidbot).
