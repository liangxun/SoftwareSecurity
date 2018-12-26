"""
从app中提取特征
"""
import os
from extract import Extractor
import json


def scan(app_dir, report_dir):
    apps = os.listdir(app_dir)
    E = Extractor()
    for app in apps:
        print('extract app{}'.format(app))
        permission, apis = E.extract(os.path.join(app_dir, app))
        report = dict()
        report['permission'] = permission
        report['apis'] = apis
        with open(os.path.join(report_dir, '{}.json'.format(app)), 'w') as f:
            json.dump(report, f)


if __name__ == '__main__':
    appdir = './data/reverse/malware'
    reportdir = './data/report/malware'
    scan(appdir, reportdir)
