#!/usr/bin/python
# coding=UTF-8
#
# JISC Format Sniffing
# Copyright (C) 2016
# All rights reserved.
#
# This code is distributed under the terms of the GNU General Public
# License, Version 3. See the text file "COPYING" for further details
# about the terms of this license.
#
""" Gathers institution ID and name data from DOI web site into a lookup map. """
import collections
import json
import os.path
from lxml import html
import requests

from corptest.utilities import ObjectJsonEncoder, create_dirs
from corptest import APP

RDSS_ROOT = APP.config.get('RDSS_ROOT')
DOI_STORE = os.path.join(RDSS_ROOT, 'doi', 'lookup.json')
DATACITE_PAGES = range(1, 4)
DATACITE_HTML_ROOT = 'https://search.datacite.org'
DATACITE_BL_QUERY = '/data-centers?member-id=bl&page='

class DataciteDoiLookup(object):
    """ Class that provides lookup of Datacite datacentre details by DOI. """
    DATACENTRES = collections.defaultdict(dict)

    def add_datacentre(self, datacentre):
        """ Adds a datacentre to the lookup map. """
        self.DATACENTRES.update({datacentre.doi : datacentre})

    @classmethod
    def lookup_by_doi(cls, doi):
        """ Looks up and returns a Datacite datacentre by DOI """
        if doi not in cls.DATACENTRES:
            return DataciteDatacentre("Unknown", doi, "")
        return cls.DATACENTRES.get(doi)

    @classmethod
    def initialise(cls, persist_to=None):
        """ If persist_to exists, tries to load a serialised lookup table from it.
        Populates lookup table and saves to persist_to if persist_to doesn't exist.
        """
        cls.DATACENTRES.clear()
        if persist_to is None:
            # No persist value passed, populate the dictionary
            cls.populate_lookup_table()
        elif os.path.isfile(persist_to):
            # Persistence file exists, load the dictionary
            lookup_file = open(persist_to, 'r')
            cls.load(lookup_file)
        else:
            # Persistence file doesn't exist
            create_dirs(os.path.dirname(persist_to))
            # populate and save the lookup dictionary
            cls.populate_lookup_table()
            lookup_file = open(persist_to, 'w')
            cls.save(lookup_file)

    @classmethod
    def populate_lookup_table(cls):
        """ Populates the lookup table using the utitility methods. """
        for datacentre_name, datacentre_page_rel_url in datacite_datacentre_iterator():
            datacentre_doi, bl_id = scrape_datacite_doi(datacentre_page_rel_url)
            if datacentre_doi != None and bl_id != None:
                datacentre = DataciteDatacentre(datacentre_name, datacentre_doi,
                                                bl_id)
                cls.DATACENTRES.update({datacentre.doi : datacentre})

    @classmethod
    def persist(cls, name=DOI_STORE):
        """Persist the DOI lookup class to file with path name."""
        with open(name, 'w+') as persit_file:
            cls.save(persit_file)

    @classmethod
    def save(cls, dest):
        """ Serialise the datacentre lookup dictionary to fp (a write() supporting
        file-like object). """
        json.dump(cls.DATACENTRES, dest, cls=ObjectJsonEncoder)

    @classmethod
    def load(cls, src):
        """ Loads the datacentre lookup dictionary from fp (a read() supporting
        file like object)."""
        cls.DATACENTRES = json.load(src, object_hook=DataciteDatacentre.json_decode)

class DataciteDatacentre(object):
    """ Skinny class to hold Datacite Datacentre details. """
    def __init__(self, name, doi, bl_id):
        self.name = name
        self.doi = doi
        self.bl_id = bl_id

    def get_name(self):
        """ Get the name of the datacentre. """
        return self.name

    def get_doi(self):
        """ Get the Digital Object Identifier (DOI) of the the datacenter. """
        return self.doi

    def get_bl_id(self):
        """ Get the British Library identifier for the datacenter. """
        return self.bl_id

    def __str__(self):
        ret_val = []
        ret_val.append("DataciteDatacentre : [doi=")
        ret_val.append(self.doi)
        ret_val.append(", name=")
        ret_val.append(self.name)
        ret_val.append(", BLID=")
        ret_val.append(self.bl_id)
        ret_val.append("]")
        return "".join(ret_val)

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for DataciteDatacentre. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            data_cent = obj[cls_name]
            return cls(data_cent['name'], data_cent['doi'], data_cent['bl_id'])
        return obj

def datacite_datacentre_iterator():
    """
    Grabs the datacite home page's HTML and then yields each entry's name and
    sub-page location, for parsing the DOI.
    """
    # Iterate through the BL institutions, page numbers currently a constant
    for datacite_page_num in DATACITE_PAGES:
        # Print format a URL for the page scrape and grab the page HTML
        datacite_url = '{}{}{}'.format(DATACITE_HTML_ROOT, DATACITE_BL_QUERY,
                                       datacite_page_num)
        datacentre_page = requests.get(datacite_url)
        datacentre_tree = html.fromstring(datacentre_page.content)
        # XQuery the work anchors, these are the data centres
        datacentre_links = datacentre_tree.xpath('//h3[@class="work"]/a')
        # Iterate the the links and yield the names and numbers
        for datacentre_link in datacentre_links:
            yield datacentre_link.text.strip(), datacentre_link.get('href')

def scrape_datacite_doi(datacentre_page_rel_url):
    """ Scrapes the DOI from a datacentre's home page and returns the DOI and
    the BL identifier as a tuple.
    """
    datacentre_url = '{}{}'.format(DATACITE_HTML_ROOT, datacentre_page_rel_url)
    datacentre_page = requests.get(datacentre_url)
    datacentre_tree = html.fromstring(datacentre_page.content)
    doi_links = datacentre_tree.xpath('//h3[@class="work"]/a')
    for doi_link in doi_links:
        scraped_href = doi_link.get('href')
        if scraped_href.startswith("/works"):
            href_parts = scraped_href.split('/')
            if len(href_parts) > 2:
                return href_parts[2], href_parts[3]
    return None, None

def main():
    """
    Main method entry point, parses DOIs from Datacite and outputs to
    STDOUT.
    """
    DataciteDoiLookup.initialise()
    for doi in DataciteDoiLookup.DATACENTRES:
        datacentre = DataciteDoiLookup.lookup_by_doi(doi)
        print(str(datacentre))

if __name__ == "__main__":
    main()
