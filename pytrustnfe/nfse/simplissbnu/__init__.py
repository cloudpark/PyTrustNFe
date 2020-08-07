# -*- coding: utf-8 -*-
import os
import requests

from lxml import etree
from pytrustnfe.xml import render_xml
from pytrustnfe.certificado import extract_cert_and_key_from_pfx, save_cert_key
from pytrustnfe.nfse.assinatura import Signer

URL = 'https://wsblumenau1.simplissweb.com.br/nfseservice.svc'
HEADERS = {'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': "http://nfse.abrasf.org.br/INfseService/GerarNfse"}


def _render_xml(method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), 'templates')
    xml_send = render_xml(path, '%s.xml' % method, True, **kwargs)
    xml_send = etree.tostring(xml_send)
    return xml_send


def _send(certificate, method, retry=0, **kwargs):
    try:
        cert_content, key_content = extract_cert_and_key_from_pfx(certificate.pfx, certificate.password)
        cert_filename, key_filename = save_cert_key(cert_content, key_content)

        path = os.path.join(os.path.dirname(__file__), 'templates')
        body = render_xml(path, '%s.xml' % method, False, **kwargs)
        body = Signer().sign_xml(body, 'L1', cert_content, key_content)

        data = '<?xml version="1.0" encoding="UTF-8"?>' \
               '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" ' \
               'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
               'xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/" ' \
               'xmlns:ns1="http://nfse.abrasf.org.br">' \
               '<SOAP-ENV:Header/>' \
               '<ns0:Body><ns1:GerarNfseRequest>' \
               '<nfseCabecMsg><![CDATA[<cabecalho versao="2.03" ' \
               'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
               'xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://www.abrasf.org.br/nfse.xsd">' \
               '<versaoDados>2.03</versaoDados></cabecalho>]]>' \
               '</nfseCabecMsg><nfseDadosMsg><![CDATA[%s]]></nfseDadosMsg></ns1:GerarNfseRequest></ns0:Body>' \
               '</SOAP-ENV:Envelope>' % body
        data = data.encode()

        session = requests.Session()
        session.cert = (cert_filename, key_filename)
        response = session.post(URL, data=data, headers=HEADERS)
        print(response.status_code)
        print(response.text)
        if response.status_code != 200 or "E900" in response.text:
            if retry <= 2:
                retry = retry + 1
                _send(certificate, method, retry, **kwargs)
            else:
                raise Exception("Erro ao exportar a RPS. %d - %s" % (response.status_code, response.text))
    except Exception as e:
        print(e)
        raise e


def gerar_nfse(certificate, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = _render_xml('GerarNfse', **kwargs)
    return _send(certificate, 'GerarNfse', 0, **kwargs)
