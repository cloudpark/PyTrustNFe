# -*- coding: utf-8 -*-
import os

from suds import WebFault
from lxml import etree
from pytrustnfe.certificado import extract_cert_and_key_from_pfx, save_cert_key
from pytrustnfe.client import get_authenticated_client
from pytrustnfe.xml import render_xml, sanitize_response


def _render_xml(method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), 'templates')
    xml_send = render_xml(path, '%s.xml' % method, True, **kwargs)
    xml_send = etree.tostring(xml_send)

    return xml_send


def _validate(method, xml):
    path = os.path.join(os.path.dirname(__file__), 'templates')
    schema = os.path.join(path, '%s.xsd' % method)

    nfe = etree.fromstring(xml)
    esquema = etree.XMLSchema(etree.parse(schema))
    esquema.validate(nfe)
    erros = [x.message for x in esquema.error_log]
    return erros


def _send(certificado, method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), 'templates')
    if kwargs['ambiente'] == 'producao':
        url = 'https://notacarioca.rio.gov.br/WSNacional/nfse.asmx?wsdl'
    else:
        url = ''

    xml_send = render_xml(path, '%s.xml' % method, False, **kwargs)
    cert, key = extract_cert_and_key_from_pfx(certificado.pfx, certificado.password)
    cert, key = save_cert_key(cert, key)
    client = get_authenticated_client(url, cert, key)

    try:
        response = getattr(client.service, method)(xml_send.decode("utf-8"))
    except WebFault as e:
        return {
            'sent_xml': xml_send,
            'received_xml': e.fault.faultstring,
            'object': None
        }

    response, obj = sanitize_response(response)
    return {
        'sent_xml': xml_send,
        'received_xml': response,
        'object': obj
    }


def xml_recepcionar_lote_rps(**kwargs):
    return _render_xml('RecepcionarLoteRps', **kwargs)


def recepcionar_lote_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = xml_recepcionar_lote_rps(**kwargs)
    return _send(certificado, 'RecepcionarLoteRps', **kwargs)


def xml_consultar_situacao_lote(**kwargs):
    return _render_xml('ConsultarSituacaoLoteRps', **kwargs)


def consultar_situacao_lote(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = xml_consultar_situacao_lote(**kwargs)
    return _send(certificado, 'ConsultarSituacaoLoteRps', **kwargs)


def xml_consultar_lote_rps(**kwargs):
    return _render_xml('ConsultarLoteRps', **kwargs)


def consultar_lote_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = xml_consultar_lote_rps(**kwargs)
    return _send(certificado, 'ConsultarLoteRps', **kwargs)
