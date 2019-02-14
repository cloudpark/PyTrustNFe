# -*- coding: utf-8 -*-
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import os
from pytrustnfe.xml import render_xml
from lxml import etree


def _render_xml(method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), 'templates')
    xml_send = render_xml(path, '%s.xml' % method, True, **kwargs)
    xml_send = etree.tostring(xml_send)
    return xml_send.encode('utf-8')


def xml_recepcionar_lote_rps(**kwargs):
    return _render_xml('RecepcionarLoteRps', **kwargs)
