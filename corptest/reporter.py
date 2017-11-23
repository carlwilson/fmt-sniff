#!/usr/bin/env python
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
""" Reporting as PDF. """
import collections
from fpdf import FPDF

class PDF(FPDF):
    """PDF report generator with header and footer."""
    def header(self):
        # Logo
        # self.image('logo_pb.png', 10, 8, 33)
        # Arial bold 15
        self.set_font('Arial', 'B', 15)
        # Move to the right
        self.cell(60)
        # Title
        self.cell(80, 10, 'JISC Format Report', 1, 0, 'C')
        # Line break
        self.ln(20)

    def cell_pair_line(self, key, value):
        """ Gen a standard PDF report line."""
        self.cell(50, 10, str(key) + ': ')
        self.cell(40, 10, str(value))
        self.ln(5)

    # Page footer
    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Arial italic 8
        self.set_font('Arial', 'I', 8)
        # Page number
        self.cell(0, 10, 'Page ' + str(self.page_no()) + '/{nb}', 0, 0, 'C')

def item_pdf_report(key, report_path):
    """Generates a PDF report for an item."""
    pdf = PDF()
    pdf.add_page()
    pdf.set_font('Arial', '', 12)
    pdf.cell_pair_line('Name', key.name)
    pdf.cell_pair_line('Path', key.value)
    pdf.cell_pair_line('Reported Size', key.size)
    pdf.cell_pair_line('Last modified', key.last_modified)
    for prop in key.properties:
        pdf.cell_pair_line(prop, key.properties[prop])
    pdf.cell_pair_line('SHA1', key.byte_sequence.sha1)
    pdf.cell_pair_line('Size', key.byte_sequence.size)
    for prop in key.byte_sequence.properties:
        pdf.cell_pair_line(prop.qualified_name, prop.prop_val.value)
    pdf.output(report_path, 'F')

def pdf_report(report, report_path):
    """Generates a PDF report for an item."""
    pdf = PDF()
    pdf.add_page()
    pdf.set_font('Arial', '', 12)
    pdf.cell_pair_line('Source', report.source.name)
    pdf.cell_pair_line('Root', report.root_key + '/')
    pdf.cell_pair_line('Files:', '')
    for key in report.keys:
        pdf.cell(10, 10, '')
        pdf.cell(20, 10, "Name")
        pdf.cell(50, 10, str(key.path))
        pdf.ln(5)
        pdf.cell(20, 10, '')
        pdf.cell(20, 10, 'Size')
        pdf.cell(50, 10, str(key.byte_sequence.size))
        pdf.ln(5)
        pdf.cell(20, 10, '')
        pdf.cell(20, 10, 'SHA1')
        pdf.cell(50, 10, key.byte_sequence.sha1)
        pdf.ln(5)
        for prop in key.byte_sequence.properties:
            pdf.cell(20, 10, '')
            pdf.cell(60, 10, str(prop.qualified_name))
            pdf.cell(60, 10, str(prop.prop_val.value))
            pdf.ln(5)

    pdf.output(report_path, 'F')

def report_to_dict(report):
    """Flattens a given report to a dictionary for reporting."""
    ret_val = collections.defaultdict()
    ret_val['Source'] = report.source.name
    ret_val['Root'] = report.root_key + '/'
    key_list = []
    for key in report.keys:
        key_list.append(key_to_dict(key))
    ret_val['Keys'] = key_list
    return ret_val

def source_key_to_dict(source_key):
    """Flattens a given key to a dictionary for reporting."""
    ret_val = collections.defaultdict()
    ret_val['Path'] = source_key.value
    ret_val['Size'] = source_key.size
    ret_val['Last modified'] = source_key.last_modified
    ret_val['Byte sequence'] = bs_to_dict(source_key.byte_sequence)
    return ret_val

def key_to_dict(key):
    """Flattens a given key to a dictionary for reporting."""
    ret_val = collections.defaultdict()
    ret_val['Path'] = key.path
    ret_val['Size'] = key.size
    # ret_val['Last modified'] = key.last_modified
    ret_val['Byte sequence'] = bs_to_dict(key.byte_sequence)
    return ret_val

def bs_to_dict(byte_sequence):
    """Flattens a given ByteSequence to a dictionary for reporting."""
    ret_val = collections.defaultdict()
    ret_val['SHA1'] = byte_sequence.sha1
    ret_val['Size'] = byte_sequence.size
    ret_val['Properties'] = props_to_dict(byte_sequence.properties)
    return ret_val

def props_to_dict(properties):
    """Flattens a given set of Properties to a dictionary for reporting."""
    ret_val = collections.defaultdict()
    for prop in properties:
        ret_val[prop.qualified_name] = prop.prop_val.value
    return ret_val
