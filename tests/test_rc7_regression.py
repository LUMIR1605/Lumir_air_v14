from contextlib import ExitStack
from unittest.mock import patch
import importlib
import pytest
from pypdf import PdfReader
from shield.multi_scan import run
from shield.truth import validate_report
from shield.html_report import build as html
from shield.pdf_report import build as pdf

@pytest.mark.parametrize('kind,target', [('email','demo@example.com'),('phone','+48123456789'),('username','synthetic_user')])
def test_no_consent_never_calls_sources(kind,target):
    with ExitStack() as stack:
        mocks=[stack.enter_context(patch('shield.multi_scan.'+n, side_effect=AssertionError('called'))) for n in ['email_scan','breach_scan','domain_scan','phone_scan','username_scan','account_exposure_scan']]
        result=run(kind,target,False)
        assert validate_report(result)
        assert all(m.call_count==0 for m in mocks)

@pytest.mark.parametrize('status', ['completed','unavailable','timeout','error'])
def test_account_results_and_score(status):
    with ExitStack() as stack:
        for name in ['email_scan','breach_scan','domain_scan']:
            stack.enter_context(patch('shield.multi_scan.'+name, return_value={'module':name,'scan_status':'unavailable','score':None}))
        stack.enter_context(patch('shield.account_exposure_scan.holehe_scan', return_value={'scan_status':status,'services':['Synthetic Service'] if status=='completed' else [],'checked':1}))
        result=run('email','demo@example.com',True)
    assert validate_report(result)
    assert result['security_assessment']['score'] is None
    assert result['services']['confirmed_count']==0
    assert result['services']['probable_count']==(1 if status=='completed' else 0)
    assert result['services']['not_found_count']==0
    assert result['services']['not_checked_count']==(0 if status=='completed' else 1)

def test_import_does_not_analyze():
    with patch('shield.core.analyze',side_effect=AssertionError('analysis on import')) as analyze:
        import test_shield
        importlib.reload(test_shield)
        analyze.assert_not_called()

@pytest.mark.parametrize('kind', ['email','phone','username'])
def test_reports_missing_data_and_escaping(tmp_path,kind):
    report=run(kind,'demo@example.com',False)
    report['security_assessment']['public_verdict']='<img src="https://example.com/tracker">'
    if kind=='email':
        report['modules'][2]['services']={'results':[{'service_name':'<script>alert(1)</script>'}]}
    h=tmp_path/'report.html'; p=tmp_path/'report.pdf'
    html(report,str(h)); pdf(report,str(p))
    text=h.read_text(encoding='utf-8')
    assert '<script>' not in text and '<img ' not in text
    content=''.join(page.extract_text() for page in PdfReader(p).pages)
    assert 'LUMIR SHIELD' in content
    if kind=='email': assert 'Account Discovery' in content

def test_source_exception_does_not_leak_details():
    with ExitStack() as stack:
        for name in ['email_scan','breach_scan','domain_scan','account_exposure_scan']:
            stack.enter_context(patch('shield.multi_scan.'+name,side_effect=RuntimeError('PRIVATE_VALUE')))
        result=run('email','demo@example.com',True)
    assert 'PRIVATE_VALUE' not in str(result)
    assert validate_report(result)


def test_holehe_discards_recovery_information():
    from shield.holehe_scan import _service_names
    _, names = _service_names("[+] example.com masked@example.com / +123 / FullName PRIVATE")
    assert names == ["example.com"]
