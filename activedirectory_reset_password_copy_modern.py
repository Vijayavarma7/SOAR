"""
This playbook resets the password of a potentially compromised user account. First, an analyst is prompted to evaluate the situation and choose whether to reset the account. If they approve, a strong password is generated and the password is reset.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################
from random import randint
from random import shuffle
################################################################################
## Global Custom Code End
################################################################################

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    reset_password(container=container)

    return

@phantom.playbook_block()
def reset_option(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("reset_option() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["reset_password:action_result.summary.responses.0", "==", "Yes"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        generate_password(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_decline_msg(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def format_decline_msg(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_decline_msg() called")

    ################################################################################
    # Formats a message stating the user declined to reset the password
    ################################################################################

    template = """Analyst declined to reset password for user: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.compromisedUserName"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_decline_msg")

    add_comment_no_reset(container=container)

    return


@phantom.playbook_block()
def add_comment_no_reset(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_no_reset() called")

    ################################################################################
    # Add the comment notifying the reader that the password reset was declined
    ################################################################################

    format_decline_msg = phantom.get_format_data(name="format_decline_msg")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_decline_msg)

    return


@phantom.playbook_block()
def format_pwd_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_pwd_message() called")

    ################################################################################
    # Formats a message about the password reset to provide in the comments
    ################################################################################

    template = """Reset user {0} password to following {1}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.compromisedUserName",
        "generate_password:custom_function:strong_password"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_pwd_message")

    add_comment_pwd_reset(container=container)

    return


@phantom.playbook_block()
def add_comment_pwd_reset(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_pwd_reset() called")

    format_pwd_message = phantom.get_format_data(name="format_pwd_message")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_pwd_message)

    return


@phantom.playbook_block()
def reset_ad_password(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("reset_ad_password() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Reset the Active Directory password of the user to the generated password
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.compromisedUserName","artifact:*.id"])
    generate_password__strong_password = json.loads(_ if (_ := phantom.get_run_data(key="generate_password:strong_password")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'reset_ad_password' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None and generate_password__strong_password is not None:
            parameters.append({
                "username": container_artifact_item[0],
                "new_password": generate_password__strong_password,
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("set password", parameters=parameters, name="reset_ad_password", assets=["active directory"])

    return


@phantom.playbook_block()
def reset_password(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("reset_password() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    role = None
    message = """Found the account \"{0}\" has a compromised credential! Would you like to automatically reset the password?"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.compromisedUserName"
    ]

    # responses
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="reset_password", parameters=parameters, response_types=response_types, callback=reset_option)

    return


@phantom.playbook_block()
def generate_password(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("generate_password() called")

    ################################################################################
    # Custom code block that generates a strong random password
    ################################################################################

    generate_password__strong_password = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    alpha = 'abcdefghijklmnopqrstuvwxyz'
    num = '0123456789'
    special = '!@#$%^&*('
    
    pwd = ''
    for i in range(5):
        pwd += alpha[randint(0, len(alpha)-1)]
        pwd += (alpha[randint(0, len(alpha)-1)]).upper()
        pwd += num[randint(0, len(num)-1)]
        pwd += special[randint(0, len(special)-1)]
    r = list(pwd)
    shuffle(r)
    generate_password__strong_password = ''.join(r)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="generate_password:strong_password", value=json.dumps(generate_password__strong_password))

    reset_ad_password(container=container)
    format_pwd_message(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return