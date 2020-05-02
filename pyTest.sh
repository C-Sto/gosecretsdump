source venv/bin/activate

if [[ ! -d "./impacket" ]]
then
    git clone https://github.com/SecureAuthCorp/impacket
fi

cd impacket
python setup.py install
cd ..
#python impacket/examples/secretsdump.py -system test/Big/SYSTEM -ntds test/Big/ntds.dit LOCAL
python impacket/examples/secretsdump.py -system test/2016/SYSTEM -ntds test/2016/ntds.dit LOCAL -history
deactivate