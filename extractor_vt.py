#!/usr/bin/env python3

"""
extracts samples from the database, preprocesses them and writes the
results to a crunchable file.
"""

import argparse
import itertools
import logging
import math
import multiprocessing
import numpy
import sys

import api
from pymongo import MongoClient
from bson.objectid import ObjectId
from multiprocessing import Pool, Lock, TimeoutError

FIELDS_TO_WRITE = ['total_a_records',
                   'pdns_a_records', 'total_urls', 'num_url_scores',
                   'num_detected_communicating_scores',
                   'num_detected_downloaded_scores', 'mean_url_scores',
                   'mean_detected_communicating_scores',
                   'mean_detected_downloaded_scores', 'median_url_scores',
                   'median_detected_communicating_scores',
                   'median_detected_downloaded_scores']

# normally i'm totally against any global variables
# but the multiprocessing serialization forces me to
FILE_WRITE_LOCK = Lock()
SAMPLE_COLLECTION = None
OUTPUT_FILE = None


def emit(result):
    """
    perform preprocessing for the extracted data.

    writes out a single entry for the file to crunch later.
    """

    fields = FIELDS_TO_WRITE
    output = list()

    for field in fields:
        dat = result.get(field, -1)
        if math.isnan(dat):
            dat = field+"NAN"
        output.append(dat)

    return (output, result['domain'], result['source'])


def analyze(analysis):
    """
    grabs values we're interested in from the database query result.
    passes extracted data to the preprocessor and
    writes the resulting data to the output file.
    """

    result = dict()

    # Check to see if we care about that sample based on its source.
    sample = SAMPLE_COLLECTION.find_one({
        "_id": ObjectId(analysis["object_id"])
    })

    source_name = set([name['name'] for name in sample["source"] ])
    #source_name = sample["source"][0]["name"]
    if len(source_name.intersection({"benign", "maltrieve", "novetta"})):
        result["source"] = source_name
    else:
        # this sample isn't interesting for us
        return

    # Found a sample we care about so begin feature extraction
    try:
        pdns_a_records = 0
        total_urls = 0
        url_scores = numpy.array([])
        detected_downloaded_scores = numpy.array([])
        detected_communicating_scores = numpy.array([])
        for element in analysis['results']:

            if item['subtype'] == "A Records":
                pdns_a_records += 1

            if element['subtype'] == "URLs":
                logging.info("domain: {}".format(element['result']))
                result['domain'] = element['result']
                result['domain_length'] = len(element['result'])
                total_urls += 1
                if item['total'] != 0:
                    numpy.append(url_scores, float(item["positives"])/float(item['total']))
                else:
                    numpy.append(url_scores, float(item["positives"])/float(55))

            if item['subtype'] == "Detected Downloaded Samples":
                if item['total'] != 0:
                    detected_downloaded_scores = numpy.append(detected_downloaded_scores, float(item["positives"])/float(item['total']))
                else:
                    detected_downloaded_scores = numpy.append(detected_downloaded_scores, float(item["positives"])/float(55))

            if item['subtype'] == "Detected Communicating Samples":
                if item['total'] != 0:
                    detected_communicating_scores = numpy.append(detected_communicating_scores, float(item["positives"])/float(item['total']))
                else:
                    detected_communicating_scores = numpy.append(detected_communicating_scores, float(item["positives"])/float(55))
        #Need a NAN conversion function. -1 for NAN?
        result['pdns_a_records'] = pdns_a_records
        result['total_urls'] = total_urls
        result['num_url_scores'] = len(url_scores)
        result['num_detected_communicating_scores'] = len(detected_communicating_scores)
        result['num_detected_downloaded_scores'] = len(detected_downloaded_scores)
        result['mean_url_scores'] = numpy.mean(url_scores)
        result['mean_detected_communicating_scores'] = numpy.mean(detected_communicating_scores)
        result['mean_detected_downloaded_scores'] = numpy.mean(detected_downloaded_scores)
        result['median_url_scores'] = numpy.median(url_scores)
        result['median_detected_communicating_scores'] = numpy.median(detected_communicating_scores)
        result['median_detected_downloaded_scores'] = numpy.median(detected_downloaded_scores)

    except TypeError:
        logging.error("type error when gathering database values!")
    except Exception as _:
        logging.error(("exception when gathering "
                       " database values:\n{}".format(sys.exc_info())))

    data_result = emit(result)
    with FILE_WRITE_LOCK:
        logging.info("data result: {}".format(data_result))
        OUTPUT_FILE.write("{}\n".format(data_result))
        OUTPUT_FILE.flush()


def main():
    """
    entry point, performs argparsing and job calling
    """

    global SAMPLE_COLLECTION
    global OUTPUT_FILE

    cmd = argparse.ArgumentParser()
    cmd.add_argument("output_file", type=argparse.FileType('w'),
                     help="file where to write results in")
    cmd.add_argument("--jobs", "-j", default=multiprocessing.cpu_count(),
                     type=int,
                     help="Number of processes to use. Default is number of CPUs")
    cmd.add_argument("--multiprocess", "-m", action="store_true",
                     help="use multiple processes for parallelization")

    args = cmd.parse_args()

    # set logging format and level
    logging.basicConfig(format='%(asctime)s => %(levelname)s: %(message)s',
                        level=logging.INFO)

    # silence requests-messages
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    # the database client
    client = MongoClient()

    # connect to databases
    database = client['crits']
    analysis_collection = database['analysis_results']
    SAMPLE_COLLECTION = database['domains']

    # Helper dictionary for finding VirusTotal analysis
    analysis_query = {
        "service_name": "virustotal_lookup",
        "status": "completed",
        "object_type": "Domain"
    }

    # I am moving through the analysis results first as they will be fewer
    # the way the data is stored also makes this easier to link back to an
    # obj_ID
    to_analyze = analysis_collection.find(analysis_query)
    sample_count = to_analyze.count()

    OUTPUT_FILE = args.output_file
    logging.info("will run over {} samples".format(sample_count))

    if args.multiprocess:
        logging.info("using multiprocessing")
        with Pool(processes=args.jobs, maxtasksperchild=100) as pool:
            try:
                pool.map_async(analyze, to_analyze).get(timeout=300)
            except TimeoutError:
                logging.info("Timeout Error: {}".format(pool))
                pool.terminate()
                pool.join()
            except:
                logging.info("Unexpected error: {}".format(sys.exc_info()[0]))

    else:
        logging.info("using a single thread")
        for val in to_analyze:
            analyze(val)


if __name__ == '__main__':
    main()
