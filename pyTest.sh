source venv/bin/activate
cd impacket
python setup.py install
cd ..
python impacket/examples/secretsdump.py -system test/Big/SYSTEM -ntds test/Big/ntds.dit LOCAL
deactivate