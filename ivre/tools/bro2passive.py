#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2017 Pierre LALET <pierre.lalet@cea.fr>
#
# IVRE is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# IVRE is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IVRE. If not, see <http://www.gnu.org/licenses/>.

"""Update the passive database from various bro logs"""


import functools
import os
import signal


import ivre.db
import ivre.utils
import ivre.passive
import ivre.parser.bro


signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)


def _get_ignore_rules(ignore_spec):
    """Executes the ignore_spec file and returns the ignore_rules
dictionary.

Python 2.6 bug: it has to be in a separate function than main()
because of the exec() call and the nested functions.

    """
    ignore_rules = {}
    if ignore_spec is not None:
        exec(compile(open(ignore_spec, "rb").read(), ignore_spec, 'exec'),
             ignore_rules)
    return ignore_rules


def rec_iter(brofile, process_bro_log, sensor, ignore_rules):
    """Yields well formated dicts for insertion into the passiverecondb.
    `brofile`: a BroFile
    `process_bro_log`: a function(dict) -> [dict] that transforms the parsed
        bro log into a list of dict with keys: timestamp, host, srvport,
        recontype, source, value, tagetval. One log can then generate zero, one
        or more passiverecon entries
    `sensor`: the sensor on which the log has been seen
    `ignore_rules`: specifies which nets/hosts to ignore

    """
    for line in brofile:
        passive_entries = process_bro_log(line)
        for entry in passive_entries:
            yield ivre.passive.handle_rec(
                sensor,
                ignore_rules.get('IGNORENETS', {}),
                ignore_rules.get('NEVERIGNORE', {}),
                **entry
            )


def parse_passiverecon(line):
    line["timestamp"] = line.pop("ts")
    # skip PassiveRecon::
    line["recon_type"] = line["recon_type"][14:]
    return [line]


BRO_PARSERS = {
    "passiverecon": parse_passiverecon,
}


def main():
    import sys
    try:
        import argparse
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('logfiles', nargs='*', metavar='FILE',
                            help='Bro log files')
    except ImportError:
        import optparse
        parser = optparse.OptionParser(description=__doc__)
        parser.parse_args_orig = parser.parse_args

        def my_parse_args():
            res = parser.parse_args_orig()
            res[0].ensure_value('logfiles', res[1])
            return res[0]
        parser.parse_args = my_parse_args
        parser.add_argument = parser.add_option

    parser.add_argument('--sensor', '-s', help='Sensor name')
    parser.add_argument('--ignore-spec', '-i',
                        help='Filename containing ignore rules')
    parser.add_argument('--bulk', action='store_true',
                        help='Use bulk inserts (this is the default)')
    parser.add_argument('--no-bulk', action='store_true',
                        help='Do not use bulk inserts')
    args = parser.parse_args()
    ignore_rules = _get_ignore_rules(args.ignore_spec)
    if (not args.no_bulk) or args.bulk:
        function = ivre.db.db.passive.insert_or_update_bulk
    else:
        function = functools.partial(
            ivre.db.DBPassive.insert_or_update_bulk,
            ivre.db.db.passive,
        )

    for fname in args.logfiles:
        if not os.path.exists(fname):
            ivre.utils.LOGGER.error("File %r does not exist", fname)
            continue
        with ivre.parser.bro.BroFile(fname) as brof:
            ivre.utils.LOGGER.debug("Parsing %s\n\t%s", fname,
                                    "Fields:\n%s\n" % "\n".join(
                                        "%s: %s" % (f, t)
                                        for f, t in brof.field_types
                                    ))
            if brof.path in BRO_PARSERS:
                process_bro_log = BRO_PARSERS[brof.path]
            else:
                utils.LOGGER.debug("Log format not (yet) supported for %r",
                                   fname)
                continue
            function(
                rec_iter(
                    brof, process_bro_log, args.sensor, ignore_rules
                ),
                getinfos=ivre.passive.getinfos
            )
