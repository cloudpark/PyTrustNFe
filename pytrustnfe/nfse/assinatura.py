# -*- coding: utf-8 -*-
# © 2016 Danimar Ribeiro, Trustcode
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

from lxml import etree
import xmlsec
import os.path
import signxml
from signxml import XMLSigner

consts = xmlsec.constants

NAMESPACE_SIG = 'http://www.w3.org/2000/09/xmldsig#'


class Assinatura(object):

    def __init__(self, cert_pem, private_key, password):
        self.cert_pem = cert_pem
        self.private_key = private_key
        self.password = password

    def _checar_certificado(self):
        if not os.path.isfile(self.private_key):
            raise Exception('Caminho do certificado não existe.')

    def assina_xml(self, xml, reference):
        self._checar_certificado()
        template = etree.fromstring(xml)

        key = xmlsec.Key.from_file(
            self.private_key, format=xmlsec.constants.KeyDataFormatPem,
            password=self.password)

        signature_node = xmlsec.template.create(
            template, c14n_method=consts.TransformInclC14N,
            sign_method=consts.TransformRsaSha1)
        template.append(signature_node)
        ref = xmlsec.template.add_reference(
            signature_node, consts.TransformSha1, uri='')

        xmlsec.template.add_transform(ref, consts.TransformEnveloped)
        xmlsec.template.add_transform(ref, consts.TransformInclC14N)

        ki = xmlsec.template.ensure_key_info(signature_node)
        xmlsec.template.add_x509_data(ki)

        ctx = xmlsec.SignatureContext()
        ctx.key = key

        ctx.key.load_cert_from_file(
            self.cert_pem, consts.KeyDataFormatPem)

        ctx.sign(signature_node)
        return etree.tostring(template) #, encoding=str)


class Signer(object):

    def sign_xml(self, xml, reference, cert, key):
        xml_element = etree.fromstring(xml)
        for element in xml_element.iter("*"):
            if element.text is not None and not element.text.strip():
                element.text = None

        signer = XMLSigner(
            method=signxml.methods.enveloped, signature_algorithm="rsa-sha1",
            digest_algorithm='sha1',
            c14n_algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315')

        ns = {}
        ns[None] = signer.namespaces['ds']
        signer.namespaces = ns

        ref_uri = ('#%s' % reference) if reference else None
        signed_root = signer.sign(
            xml_element, key=key.encode(), cert=cert.encode(),
            reference_uri=ref_uri)
        if reference:
            element_signed = signed_root.find(".//*[@Id='%s']" % reference)
            signature = signed_root.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
            if element_signed is not None and signature is not None:
                parent = element_signed.getparent()
                parent.append(signature)
        return etree.tostring(signed_root).decode("utf-8")
