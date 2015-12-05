import json
import urllib.request
import urllib.error
import time
from queue import Queue
from threading import Thread


def get_url(a_queue, a_url):
    # Pre: a_url is a legitimate URL
    # Post: the json encoded response is put into a_queue
    # Post: if a rate limit HTTPError is ecountered sleep 10 seconds and try second request
    try:
        response = urllib.request.urlopen(a_url).read()
    except urllib.error.HTTPError as error:
        # If server responds with HTTP Rate Limit error 429
        # sleep and try the request again
        if error.code == 429:
            time.sleep(10)
            response = urllib.request.urlopen(a_url).read()
        else:
            print(error)

    # decode the byte response from and load as json
    json_response = json.loads(response.decode('utf-8'))
    a_queue.put(json_response)


def online_hash_lookup_by_leakedb_api(accounts_list):
    # Intent: check http://api.leakdb.net for each hash stored in accounts_list
    # Precondition: accounts_list has each key as a username and the value
    #               associated with the key is a list of hashed passwords
    # Precondition: able to reach api.leakdb.net over the internet
    # Post condition: generates list of urls to get
    # Post condition: multiple threads are called and the responses are placed into queues
    # Post condition: prints the username and crack attempt results to console

    ntlm_urls = []
    lm_urls = []
    ntlm_queue = Queue()
    lm_queue = Queue()

    for each_user in accounts_list:
        # request this each_user ntlm hash from LeakDB API
        ntlm_urls.append('https://api.leakdb.net/?j=%s' % each_user.ntlm)
        lm_urls.append('https://api.leakdb.net/?j=%s' % each_user.lm)

    for url in ntlm_urls:
        thread = Thread(target=get_url, args=(ntlm_queue, url))
        thread.start()

    for url in lm_urls:
        thread = Thread(target=get_url, args=(lm_queue, url))
        thread.start()

    for this_user in accounts_list:
        if(ntlm_queue.not_empty):
            json = ntlm_queue.get()
            if json['found'] == "true":
                this_user.cracked(json['hashes'][0]['plaintext'])
                this_user.update_status("successfully cracked by ntlm online lookup")
        if(lm_queue.not_empty):
            json = lm_queue.get()
            if json['found'] == "true":
                this_user.cracked(json['hashes'][0]['plaintext'])
                this_user.update_status("successfully cracked by lm online lookup")
    return

