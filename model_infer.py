'''
 *	
 * Copyright (c) 2016 Cisco Systems, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * 
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
'''

from classifier import LogRegClassifier
import numpy as np
import json
import math
import time
import os
import random
import argparse
from pull_data_infer import Pull_infer
from sklearn.model_selection import train_test_split
from sklearn import metrics
from sklearn.externals import joblib
from sklearn.ensemble import RandomForestClassifier


parser = argparse.ArgumentParser(description="Generate Model Parameters for LAUI", add_help=True)
parser.add_argument('-p', '--pos_dir', action="store", help="Directory of Positive Examples (JSON Format)")
parser.add_argument('-n', '--neg_dir', action="store", help="Directory of Negative Examples (JSON Format)")
parser.add_argument('-m', '--meta', action="store_true", default=False, help="Parse Metadata Information")
parser.add_argument('-l', '--lengths', action="store_true", default=False, help="Parse Packet Size Information")
parser.add_argument('-t', '--times', action="store_true", default=False, help="Parse Inter-packet Time Information")
parser.add_argument('-d', '--dist', action="store_true", default=False, help="Parse Byte Distribution Information")
parser.add_argument('-s', '--ssl', action="store_true", default=False, help="Parse SSL/TLS Information")
parser.add_argument('-o', '--output', action="store", default="params.txt", help="Output file for parameters")
parser.add_argument('-model', '--model_dir', default="/root", help="model_save_dir")
args = parser.parse_args()


SoftWare_LABELS = {
    'Google free vpn': (0, 'vpn_tencent_video'),
    'Lantern': (1, 'lantern_google_music'),
    'Psiphon': (2, 'psi_yotube'),
    'Shadowsocks': (3, 'shaowsock_you'),
    'Tor': (4, 'standby')
}


def num2class(n):
    x = SoftWare_LABELS.items()
    for name, item in x:
        if n in item:
            return name


def find_files(root_dir):
    file_list = []
    for parent, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            file_list.append(filename)
        print("file list is ", file_list)
    return file_list


def load_and_joy(file_dir, type_dir):
    # file_dir = "/home/data"
    pcap_file = find_files(file_dir)
    store_dir = os.path.join("/wwt/data", type_dir)
    # create path in /home
    isExists = os.path.exists(store_dir)
    if not isExists:
        os.makedirs(store_dir)
        print("dir created")
    else:
        print("dir already exists")
    for file in pcap_file:
        main_name = file.split('.pcap')
        file_addr = os.path.join(file_dir, file)
        command = '/home/joy/joy/bin/joy' + ' bidir=1' + ' dist=1 ' + file_addr + ' > ' + store_dir +'/' + main_name[0]+'.gz'
        print("command is ", command)
        os.system(command)
    return store_dir + '/'


def main():
    time_begin = time.time()
    max_files = [None, None]
    compact = 1
    types = []
    if args.meta:
        types.append(0)
    if args.lengths:
        types.append(1)
    if args.times:
        types.append(2)
    if args.dist:
        types.append(3)
    if args.ssl:
        types.append(4)

    print("type num is ", types)
    if types == []:
        print ('Enter some data types to learn on (-m, -l, -t, -d, -s)')
        return

    param_file = args.output
    # add1 by wwt just for test
    # tips /wwt/data wwt means the mount path in docker container
    # pos_dir = load_and_joy("/wwt/data/class1", "class_pos")
    # neg_dir = load_and_joy("/wwt/data/class2", "class_neg")
    # just for test, should be remove later
    class_1 = "/wwt/data/class_pos/"
    class_2 = "/wwt/data/class_neg/"
    class_3 = "/wwt/data/class_wwt/"
    class_4 = "/wwt/data/class_wwt2/"

    # d = Pull(types, compact, max_files, pos_dir=pos_dir, neg_dir=neg_dir, class_3=class_3, class_4=class_4)
    # data = d.data
    # labels = d.labels
    d = Pull_infer(class_3, types, compact)
    data = d.data
    origin_data = d.origin
    # print("this is data type ", np.array(origin_data).shape)
    # print("this is data size", origin_data[0], type(origin_data), type(origin_data[0]))

    num_params = 0
    for t in types:
        if t == 0:
            print ('\tMetadata\t\t(7)')
            num_params += 7
        elif t == 1 and compact == 0:
            print ('\tPacket Lengths\t\t(3600)')
            num_params += 3600
        elif t == 1 and compact == 1:
            print ('\tPacket Lengths\t\t(100)')
            num_params += 100
        elif t == 2 and compact == 0:
            print ('\tPacket Times\t\t(900)')
            num_params += 900
        elif t == 2 and compact == 1:
            print ('\tPacket Times\t\t(100)')
            num_params += 100
        elif t == 3:
            print ('\tByte Distribution\t(256)')
            num_params += 256
        elif t == 4:
            print ('\tTLS Information\t\t(198)')
            num_params += 198
    print ('Total Features:\t%i' % (num_params))
    # this just for get trained model
    # clf = RandomForestClassifier(n_estimators=100)
    # clf = clf.fit(x_train, y_train)
    # joblib.dump(clf, "/wwt/model/wwt_test_4.pkl")
    # load model has trained
    clf = joblib.load("/wwt/model/wwt_test_4.pkl")

    # result
    # np.set_printoptions(threshold=np.inf)
    predicted = clf.predict(data)
    predicted = np.array(predicted)
    result = []
    for i in predicted:
        soft_name = num2class(i)
        result.append(soft_name)
    print("result is {}, result_name is {}".format(predicted, result))
    # append list and result
    if len(origin_data) != len(result):
        print("origin_flow length is not equal to result length")
        return None
    else:
        for i, item in enumerate(result):
            origin_data[i]["result"] = item
    # save json to /wwt/data
    with open("/wwt/data/result/result.json", "w") as f:
        f.write(json.dumps(origin_data))
    time_end = time.time()
    print("total time is ", time_end-time_begin)


if __name__ == "__main__":
    main()