import os
from parsel import Selector


class Extractor:
    def __init__(self):
        self.sensitive_apis = self.getSensitiveAPIs()

    def getSensitiveAPIs(self, dictpath="./data/mapping_5.1.1.csv"):
        """建立敏感API字典"""
        APIs = set()
        with open(dictpath, 'r') as f:
            for line in f.readlines():
                CallerClass, CallerMehod = line.split(',')[:2]
                api = 'L' + CallerClass + ';->' + CallerMehod
                api = api.strip()
                APIs.add(api)
        print("build dict: contain {} sensitive APIs.".format(len(APIs)))
        return APIs

    def parse_manifest(self, xml):
        """
        分析Manifest
        提取申请权限
        :param xml:
        :return:
        """
        doc = Selector(xml)
        uses_permissions = [i.attrib['android:name'] for i in doc.xpath('//uses-permission')]
        return uses_permissions

    def analysis_smali(self, smalidir):
        """
        分析smali代码
        提取敏感API
        :param smalidir:
        :return:
        """
        smalis = []
        for (root, dirs, files) in os.walk(smalidir):
            for file in files:
                smalis.append(os.path.join(root, file))

        apis = []
        for smali in smalis:
            with open(smali, 'r') as f:
                for line in f.readlines():
                    line = line.strip()
                    if line.startswith('invoke'):
                        func = line.split(' ')[-1]
                        func = func[:func.index('(')]
                        if func in self.sensitive_apis:
                            apis.append(func)
        return apis

    def extract(self, app):
        assert os.path.exists(os.path.join(app, 'smali'))
        assert os.path.exists(os.path.join(app, 'AndroidManifest.xml'))
        with open(os.path.join(app, 'AndroidManifest.xml'), 'r', encoding='utf-8') as f:
            manifest = f.read()
        uses_permissions = self.parse_manifest(manifest)
        apis = self.analysis_smali(os.path.join(app, 'smali'))
        print(len(uses_permissions))
        print(len(apis))
        return uses_permissions, apis


if __name__ == '__main__':
    E = Extractor()
    app = './data/reverse/malware/1'
    E.extract(app)

