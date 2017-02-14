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
import sys
from lxml import html
import requests
from const import DATACITE_HTML_ROOT, DATACITE_PAGES, DATACITE_PAGE_QUERY

# Temp hack to set up UTF-8 encoding
reload(sys)
sys.setdefaultencoding('utf-8')

class DataciteDoiLookup(object):
    """ Class that provides lookup of Datacite datacentre details by DOI. """
    DATACENTRES = collections.defaultdict(dict)

    def add_datacentre(self, datacentre):
        """ Adds a datacentre to the lookup map. """
        self.DATACENTRES.update({datacentre.doi : datacentre})

    @classmethod
    def lookup_by_doi(cls, doi):
        """ Looks up and returns a Datacite datacentre by DOI """
        return cls.DATACENTRES.get(doi)

    @classmethod
    def populate_lookup_table(cls):
        """ Populates the lookup table using the utitility methods. """
        for datacentre_name, datacentre_page_rel_url in datacite_datacentre_iterator():
            datacentre_doi, bl_id = scrape_datacite_doi(datacentre_page_rel_url)
            if datacentre_doi != None and bl_id != None:
                datacentre = DataciteDatacentre(datacentre_name, datacentre_doi,
                                                bl_id)
                print "adding : ", datacentre_name
                cls.DATACENTRES.update({datacentre.doi : datacentre})

class DataciteDatacentre(object):
    """ Skinny class to hold Datacite Datacentre details. """
    def __init__(self, name, doi, bl_id):
        self.name = name
        self.doi = doi
        self.bl_id = bl_id

    def __str__(self):
        return 'DataciteDatacentre ' + \
               '[doi : {}, name : {}, BLID : {}]'.format(self.doi,
                                                         self.name,
                                                         self.bl_id)

def datacite_datacentre_iterator():
    """
    Grabs the datacite home page's HTML and then yields each entry's name and
    sub-page location, for parsing the DOI.
    """
    # Iterate through the BL institutions, page numbers currently a constant
    for datacite_page_num in DATACITE_PAGES:
        # Print format a URL for the page scrape and grab the page HTML
        datacite_url = '{}{}{}'.format(DATACITE_HTML_ROOT, DATACITE_PAGE_QUERY,
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
    DataciteDoiLookup.populate_lookup_table()
    for doi in DataciteDoiLookup.DATACENTRES:
        datacentre = DataciteDoiLookup.lookup_by_doi(doi)
        print str(datacentre)
        # print 'Datacentre lookup {} yields {} '.format(doi,
        #                                                datacentre.name) + \
        #       'DOI {} and BL ID {}'.format(datacentre.doi,
        #                                    datacentre.bl_id)
    #     datacentre_doi, bl_id = scrape_datacite_doi(datacentre_page_rel_url)
    #     if datacentre_doi != None and bl_id != None:

if __name__ == "__main__":
    main()
