#!/usr/bin/python3
#
#  testPage.py - Soft token input test page generator script
#  Copyright (C) 2018 Zoltan Puskas <zoltan@sinustrom.info>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import logging
import sh
import shutil
import sys
import os

log = logging.getLogger('testPage')

# Constant publicly available secret key, Never use it in production!
SECRET = 'HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ'

# Minimal but sufficient set of test cases to test all soft token capabilities
# "mode", 'hash', 'factor', 'digits'
TEST_CASES = [
    ['TOTP', 'SHA1', '30', '6'],    # Default settings
    ['TOTP', 'SHA1', '30', '7'],    # 7 digits code
    ['TOTP', 'SHA1', '30', '8'],    # 8 digits code
    ['TOTP', 'SHA1', '60', '6'],    # Non standard timeout
    ['TOTP', 'SHA256', '30', '6'],  # SHA256 hash
    ['TOTP', 'SHA512', '30', '6'],  # SHA512 hash
    ['HOTP', 'SHA1', '42', '6'],    # Default settings
    ['HOTP', 'SHA1', '42', '7'],    # 7 digits code
    ['HOTP', 'SHA1', '42', '8'],    # 8 digits code
    ['HOTP', 'SHA256', '42', '6'],  # SHA256 hash
    ['HOTP', 'SHA512', '42', '6'],  # SHA512 hash
]

# Template for a basic HTML page to display all test QR codes
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>oathuri - OATH Soft token test page</title>
  <meta charset="UTF-8">
  <meta name="author" content="Zoltan Puskas">
  <meta name="description" content="OATH two-factor authenticator application test page">
  <meta name="keywords" content="oathuri, OATH, OATH-URI, two-factor, authentication, QR code, test">
  <style>
    .column-left{{ float: left; width: 33%; text-align: center }}
    .column-right{{ float: right; width: 33%; text-align: center }}
    .column-center{{ display: inline-block; width: 33%; text-align: center }}
  </style>
</head>
<body>
  <div class="container">
    {content}
  </div>
</body>
</html>
"""

# Column number to DIV style map
COL2DIV = {
    0: 'column-left',
    1: 'column-center',
    2: 'column-right',
}

def main(argv):
    html_content = []
    html_content.append('<h1>oathuri - OATH soft token test inputs</h1>')
    html_content.append('<h3>Captions: [Type]-[Hash]-[OTP lenght]-[Time window/Counter]</h3>')

    # Clean any previous output and create a new directory for the test page
    output_path = os.path.join(os.getcwd(), 'oath_test_page')
    if os.path.exists(output_path):
        shutil.rmtree(output_path)
    os.mkdir(output_path)

    # Extend executable PATH with project build directory
    PATHS = os.getenv('PATH').split(':')
    PATHS.append(os.path.normpath(os.path.join(os.getcwd(), '../bin')))

    # Get the commands to generate test page
    try:
        oathuri = sh.Command('oathuri', PATHS)
        qrencode = sh.Command('qrencode', PATHS)
    except sh.CommandNotFound:
        log.error('"oathuri" or "qrencode" were not found, cannot generate!')
        sys.exit(-1)

    cnt = 0
    columns = {
        0: [],
        1: [],
        2: [],
    }
    # Generate column content
    for mode, algo, factor, digit in TEST_CASES:
        # Get uri string to encode, name each account different per test case
        # for easy identification in apps
        account = '{}-{}-{}-{}'.format(mode, algo, digit, factor)
        args = [
            '-0',
            '-m', mode,
            '-d', digit,
            '-{}'.format('p' if mode == 'TOTP' else 'c'), factor,
            '-h', algo,
            SECRET,
            account,
            'test'
        ]
        uri = oathuri(args)

        # Generate a PNG QR code to for app scan tests
        png = '{}.png'.format(account)
        sh.qrencode('-s', '5', '-o', os.path.join(output_path, png), uri)

        # Add the test case into a column file
        columns[cnt % 3].append(
            '<figure>'
            ' <img src="{}" />'
            ' <figcaption>{}</figcaption>'
            '</figure>'.format(png, account)
        )
        cnt += 1

    # Append column data into HTML
    for col, figures in columns.items():
        html_content.append('<div class={}>'.format(COL2DIV[col]))
        html_content.append('\n'.join(figures))
        html_content.append('</div>')

    # Save content
    with open(os.path.join(output_path, 'index.html'), 'w') as html_file:
        html_file.write(HTML_TEMPLATE.format(content='\n'.join(html_content)))


if __name__ == "__main__":
    main(sys.argv)
