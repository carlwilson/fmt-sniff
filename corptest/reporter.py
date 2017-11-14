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
from fpdf import FPDF

class PDF(FPDF):
    """PDF report generator with header and footer."""
    def header(self):
        # Logo
        # self.image('logo_pb.png', 10, 8, 33)
        # Arial bold 15
        self.set_font('Arial', 'B', 15)
        # Move to the right
        self.cell(80)
        # Title
        self.cell(80, 10, 'JISC Format Report', 1, 0, 'C')
        # Line break
        self.ln(20)

    def cell_pair_line(self, key, value):
        """ Gen a standard PDF report line."""
        self.cell(50, 10, str(key) + ': ')
        self.cell(40, 10, str(value))
        self.ln(10)

    # Page footer
    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Arial italic 8
        self.set_font('Arial', 'I', 8)
        # Page number
        self.cell(0, 10, 'Page ' + str(self.page_no()) + '/{nb}', 0, 0, 'C')

def item_pdf_report(key, properties, report_path):
    """Generates a PDF report for an item."""
    pdf = PDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    pdf.cell_pair_line('Name', key.name)
    pdf.cell_pair_line('Path', key.value)
    pdf.cell_pair_line('Size', key.size)
    pdf.cell_pair_line('Last modified', key.last_modified)
    for prop in properties:
        pdf.cell_pair_line(prop, properties[prop])
    pdf.output(report_path, 'F')
