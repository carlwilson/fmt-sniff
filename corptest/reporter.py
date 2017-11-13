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

    # Page footer
    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Arial italic 8
        self.set_font('Arial', 'I', 8)
        # Page number
        self.cell(0, 10, 'Page ' + str(self.page_no()) + '/{nb}', 0, 0, 'C')

def item_pdf_report(item, report_path):
    pdf = PDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    _dict = item.to_dict()
    for key in _dict:
        pdf.cell(50, 10, key + ': ')
        pdf.cell(40, 10, str(_dict[key]))
        pdf.ln(10)
    pdf.output(report_path, 'F')
