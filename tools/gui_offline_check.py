from pathlib import Path
import socket,subprocess,json
from unittest.mock import patch
from contextlib import ExitStack
from pypdf import PdfReader
import lumir_shield_app as gui
from shield.truth import module_placeholder
out=Path('../../outputs/RC7_GUI_TEST').resolve();out.mkdir(exist_ok=True)
def module(name):return module_placeholder(name,'unavailable','SYNTHETIC OFFLINE TEST',100)
with ExitStack() as st:
 st.enter_context(patch.object(socket.socket,'connect',side_effect=RuntimeError('OFFLINE')))
 st.enter_context(patch.object(subprocess,'Popen',side_effect=RuntimeError('OFFLINE')))
 for name in ['email_scan','breach_scan','domain_scan','phone_scan','username_scan','account_exposure_scan']:
  st.enter_context(patch('shield.multi_scan.'+name,return_value=module(name)))
 st.enter_context(patch('shield.report_paths.reports_directory',return_value=out))
 st.enter_context(patch.object(gui,'ensure_reports_directory',return_value=out))
 app=gui.LumirShieldApp();app.update()
 for kind,target in [('email','demo@example.com'),('phone','+48123456789'),('username','synthetic_user')]:
  app._run(kind,target)
  events=[]
  while not app.events.empty():events.append(app.events.get())
  assert events[-1][0]=='success',events
  paths,_=events[-1][1]
  data=json.loads(paths['json'].read_text(encoding='utf-8'));assert data['scan_type']==kind
  assert 'LUMIR SHIELD' in paths['html'].read_text(encoding='utf-8')
  assert all(page.extract_text() for page in PdfReader(paths['pdf']).pages)
 app.destroy()
print('GUI Tk startup and actual GUI export pipeline: 3/3 synthetic HTML/PDF/JSON OK')
