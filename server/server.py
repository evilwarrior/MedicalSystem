#! /usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Server


from __future__ import print_function

import os, select, socket, sys, json, configparser, math
import sqlite3 as sql
import botan2 as botan
from base64 import b64encode, b64decode
from datetime import datetime

from OpenSSL import SSL, crypto


dir = os.path.dirname(sys.argv[0])
if dir == '':
    dir = os.curdir


# Botan library functions
def gen_key(bytes):
    return botan.RandomNumberGenerator().get(bytes)

def encrypt(key, ptxt):
    iv = botan.RandomNumberGenerator().get(16)
    cipher = botan.SymmetricCipher('AES-256/GCM')
    cipher.set_key(key)
    cipher.start(iv)
    ctxt = cipher.finish(ptxt.encode('utf-8'))
    cipher.clear()
    return (iv, ctxt)
# Encrypt for simple
def enc(ptxt):
    # string to base64 unicode
    def s2b64(ctxt):
        return b64encode(ctxt).decode('utf-8')
    ctxt = encrypt(key, ptxt)
    return '%s&%s' %tuple(map(s2b64, ctxt))

def decrypt(iv, key, ctxt):
    cipher = botan.SymmetricCipher('AES-256/GCM', False)
    cipher.set_key(key)
    cipher.start(iv)
    ptxt = cipher.finish(ctxt)
    cipher.clear()
    return ptxt.decode('utf-8')
# Decrypt for simple
def dec(ctxt):
    # base64 unicode to string
    def b642s(b64):
        return b64decode(b64.encode('utf-8'))
    b64 = ctxt.split('&')
    ctxt = tuple(map(b642s, b64))
    return decrypt(ctxt[0], key, ctxt[1])

def tag(pwd):
    return botan.bcrypt(pwd, botan.RandomNumberGenerator(), 11)

def varify(pwd, hash):
    return botan.check_bcrypt(pwd, hash)

# Other used functions
# To serialize type in terms of fields of tables in databases
def serialize(type):
    if type == '帐号' or type == '病历号':
        return 0
    if type == '姓名':
        return 1
    if type == '入院日期':
        return 4
    if type == '记录日期':
        return 5


# Models functions
#   Login model
def login(req):
    conn = sql.connect(dir_pdb)
    cursor = conn.cursor()
    cursor.execute(r"SELECT Name, Passwd, Is_Admin FROM User WHERE ID='%s'" %req['account'])
    record = cursor.fetchone()
    cursor.close()
    conn.close()
    if record and varify(req['passwd'], record[1]):
        is_admin = dec(record[2])
        if is_admin == 'y':
            res = search(2, '')
            res['stat'] = 'PassAdmin'
            res = (json.dumps(res), 0)
        elif is_admin == 'n':
            name = dec(record[0])
            res = search(1, '', req['account'])
            res['stat'] = 'PassMed'
            res['name'] = name
            res = (json.dumps(res), 1)
        else:
            res = (json.dumps({'stat': 'Unexpected'}), -1)
    else:
        res = (json.dumps({'stat': 'IdPwdErr'}), -1)
    return res

#   Add User model
def add_user(record):
    return op_db(record, True)

#   Modify User model
def mod_user(record):
    return op_db(record)

#   Add EMR model
def add_emr(record, op_id):
    return op_db(record, True, True, op_id)

#   Modify EMR model
def mod_emr(record, op_id):
    return op_db(record, is_emr=True, op_id=op_id)

#   Specify EMR model
def detail(emr_id, aid):
    conn = sql.connect(dir_emrdb)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Statistic_Info WHERE ID = '%s'" %emr_id)
    stat = cursor.fetchone()
    recorder = dec(stat[-1])
    if recorder != aid:
        return False

    stat = tuple(map(dec, (field for field in stat[1:13])))

    cursor.execute("SELECT CC FROM EMR WHERE ID = '%s'" %emr_id)
    cc = dec(cursor.fetchone()[0])

    cursor.execute("SELECT * FROM Anamnesis WHERE ID = '%s'" %emr_id)
    anamnesis = cursor.fetchone()
    anamnesis = tuple(map(dec, (field for field in anamnesis[1:])))

    cursor.execute("SELECT Description FROM Examination WHERE ID = '%s'" %emr_id)
    exam = dec(cursor.fetchone()[0])

    cursor.execute("SELECT * FROM Diagnosis WHERE ID = '%s'" %emr_id)
    dx = cursor.fetchone()
    dx = tuple(map(dec, (field for field in dx[1:])))

    cursor.execute("SELECT * FROM Medical_Advice WHERE ID = '%s'" %emr_id)
    advice = cursor.fetchone()
    advice = tuple(map(dec, (field for field in advice[1:])))

    cursor.close()
    conn.close()

    record = (stat, cc, anamnesis, exam, dx, advice)
    return record

#   Delete User model
def del_user(aid):
    conn = sql.connect(dir_pdb)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM User WHERE ID = '%s'" %aid)
    record = cursor.fetchone()
    try :
        if record:
            cursor.execute("DELETE FROM User WHERE ID = '%s'" %aid)
            conn.commit()
        else:
            raise Exception
    except:
        return json.dumps({'stat': 'Unexpected'})

    cursor.close()
    conn.close()

    return json.dumps({'stat': 'Success'})

#   Delete EMR model
def del_emr(emr_id):
    conn = sql.connect(dir_emrdb)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM EMR WHERE ID = '%s'" %emr_id)
    record = cursor.fetchone()
    import traceback
    try :
        if record:
            error = False
            cursor.execute("DELETE FROM EMR WHERE ID = '%s'" %emr_id)

            cursor.execute("SELECT * FROM Statistic_Info WHERE ID = '%s'" %emr_id)
            record = cursor.fetchone()
            if record:
                cursor.execute("DELETE FROM Statistic_Info WHERE ID = '%s'" %emr_id)
            else:
                error = True

            cursor.execute("SELECT * FROM Anamnesis WHERE ID = '%s'" %emr_id)
            record = cursor.fetchone()
            if record:
                cursor.execute("DELETE FROM Anamnesis WHERE ID = '%s'" %emr_id)
            else:
                error = True

            cursor.execute("SELECT * FROM Examination WHERE ID = '%s'" %emr_id)
            record = cursor.fetchone()
            if record:
                cursor.execute("DELETE FROM Examination WHERE ID = '%s'" %emr_id)
            else:
                error = True

            cursor.execute("SELECT * FROM Diagnosis WHERE ID = '%s'" %emr_id)
            record = cursor.fetchone()
            if record:
                cursor.execute("DELETE FROM Diagnosis WHERE ID = '%s'" %emr_id)
            else:
                error = True

            cursor.execute("SELECT * FROM Medical_Advice WHERE ID = '%s'" %emr_id)
            record = cursor.fetchone()
            if record:
                cursor.execute("DELETE FROM Medical_Advice WHERE ID = '%s'" %emr_id)
            else:
                error = True

            conn.commit()
            if error:
                raise Exception
        else:
            raise Exception
    except:
        traceback.print_exc()
        return json.dumps({'stat': 'Unexpected'})

    cursor.close()
    conn.close()

    return json.dumps({'stat': 'Success'})

#   Search model
def search(type, keywd, stuff=None):
    if stuff is None:
        conn = sql.connect(dir_pdb)
        cursor = conn.cursor()
        if type == 0 and keywd:
            cursor.execute(r"SELECT ID, Name, Is_Admin FROM User WHERE ID='%s'" %keywd)
        else:
            cursor.execute(r"SELECT ID, Name, Is_Admin FROM User")

        records = cursor.fetchall()
        id_records = tuple(r[0] for r in records)
        name_records = tuple(map(dec, (r[1] for r in records)))
        is_admin_records = tuple(map(dec, (r[2] for r in records)))
        tmp_records = tuple((id_records[i], name_records[i], is_admin_records[i]) for i in range(0, len(records)))

        if type == 1 and keywd:
            records = []
            for record in tmp_records:
                if record[type] == keywd:
                    records.append(record)
        else:
            records = tmp_records

        cursor.close()
        conn.close()
        res = {'records': records}
    else:
        records = search_med(type, keywd, stuff)
        res = {'records': records}

    return res



#   Medical part of Search (and Login) model
def search_med(type, keywd, stuff):
    conn = sql.connect(dir_emrdb)
    cursor = conn.cursor()
    if type == 0 and keywd:
        cursor.execute("SELECT ID, Name, Sex, Age, Admission_Date, Record_Date, Recorder \
FROM Statistic_Info WHERE ID='%s'" %keywd)
    else:
        cursor.execute("SELECT ID, Name, Sex, Age, Admission_Date, Record_Date, Recorder \
FROM Statistic_Info")

    records = cursor.fetchall()
    recorder_records = tuple(map(dec, (r[6] for r in records)))
    if type != 0 and keywd:
        type_records = tuple(map(dec, (r[type] for r in records)))
    allowed_records = []
    for i, recorder in enumerate(recorder_records):
        if recorder == stuff:
            if type != 0 and keywd and type_records[i] != keywd:
                continue
            record = records[i]
            tmp = list(map(dec, (field for field in record[1:6])))
            tmp.insert(0, record[0])
            allowed_records.append(tmp)

    cursor.close()
    conn.close()
    return allowed_records

#   Common codes with add_user() and mod_user() and add_emr() and mod_emr()
def op_db(record, is_add=False, is_emr=False, op_id=None):
    if is_emr:
        emr_id = record[0]
        name = record[1][0]
        sex = record[1][1]
        age = record[1][2]
        admission = record[1][8]
        record_d = (emr_id, name, sex, age, admission)
    else:
        account = record[0]
        name = record[1]
        passwd = record[2]
        is_admin = record[3]
        record_d = record
    flag = True
    for field in record_d:
        if field == '':
            flag = False
            break
    error = False
    if flag:
        if is_emr:
            error = fields_filter(record)
        else:
            if len(account) < 5 or len(account) > 20:
                error = '帐号长度需要在5到20之间'
            elif len(name) > 20:
                error = '姓名长度需要在20之内'
            elif len(passwd) < 8 or len(passwd) > 30:
                error = '口令长度需要在8到30之间'
            elif is_admin != 'y' and is_admin != 'n':
                error = '管理员权限仅允许输入是或否'
        if not error:
            try:
                if is_emr:
                    # insert into EMR db
                    # or update
                    record_date = datetime.now().strftime('%Y/%m/%d')
                    error = op_db_med(record, record_date, is_add, op_id)
                    if not is_add and isinstance(error, tuple):
                        (error, record_date) = error
                else:
                    # insert into permission db
                    # or update
                    name = enc(name)
                    is_admin = enc(is_admin)
                    passwd = tag(passwd)
                    conn = sql.connect(dir_pdb)
                    cursor = conn.cursor()
                    cursor.execute(r"SELECT ID FROM User WHERE ID='%s'" %account)
                    aid = cursor.fetchone()
                    if aid:
                        if is_add:
                            error = '已存在该账户'
                        else:
                            sql_handle = \
"UPDATE User SET Name='%s', Passwd='%s', Is_Admin='%s' WHERE id='%s'\
" %(name, passwd, is_admin, account)
                            cursor.execute(sql_handle)
                            conn.commit()
                    else:
                        if is_add:
                            sql_handle = \
"INSERT INTO User (ID, Name, Passwd, Is_Admin) VALUES ('%s', '%s', '%s', '%s')\
" %(account, name, passwd, is_admin)
                            cursor.execute(sql_handle)
                            conn.commit()
                        else:
                            error = -1
                    cursor.close()
                    conn.close()
            except:
                error = -1
    else:
        if is_emr:
            error = '请输入病历的关键信息！'
        else:
            error = '请输入用户的全部信息！'
    if error:
        if error == -1:
            res = json.dumps({'stat': 'Unexpected'})
        else:
            res = json.dumps({'stat': 'Failed', 'error': error})
    else:
        if is_emr:
            res = json.dumps({'stat': 'Success', 'date': record_date})
        else:
            res = json.dumps({'stat': 'Success'})
    return res

#   Medical part of Add EMR model(and Modify EMR model)
def op_db_med(record, record_date, is_add, op_id):
    error = False
    emr_id = record[0]

    conn = sql.connect(dir_emrdb)
    cursor = conn.cursor()
    cursor.execute(r"SELECT ID, Record_Date FROM Statistic_Info WHERE ID='%s'" %emr_id)
    exists = cursor.fetchone()
    if exists:
        if is_add:
            error = '已存在该病历'
        else:
            record_date = dec(exists[1])

            encd = enc_emr(record)

            name = encd['name']
            sex = encd['sex']
            age = encd['age']
            place = encd['place']
            marital_st = encd['marital_st']
            nation = encd['nation']
            occupation = encd['occupation']
            address = encd['address']
            admission = encd['admission']
            history = encd['history']
            source = encd['source']

            cc = encd['cc']

            hpi = encd['hpi']
            pmh = encd['pmh']
            ph = encd['ph']
            ogh = encd['ogh']
            fh = encd['fh']

            exam_dscr = encd['exam_dscr']

            dx_dscr = encd['dx_dscr']
            dx_sign = encd['dx_sign']

            advice_dscr = encd['advice_dscr']
            advice_sign = encd['advice_sign']

            sql_handle = \
"UPDATE EMR SET CC='%s' WHERE ID='%s'" %(cc, emr_id)
            cursor.execute(sql_handle)
            sql_handle = \
"UPDATE Statistic_Info SET \
Name='%s', Sex='%s', Age='%s', Permanent_Place='%s', Marital_St='%s',\
Nation='%s', Occupation='%s', Address='%s', Admission_Date='%s',\
History_Taking_Date='%s', History_Source='%s' WHERE ID='%s'"\
%(name, sex, age, place, marital_st, nation, occupation, address, admission,\
history, source, emr_id)
            cursor.execute(sql_handle)
            sql_handle = \
"UPDATE Anamnesis SET HPI='%s', PMH='%s', PH='%s', OGH='%s', FH='%s' \
WHERE ID='%s'" %(hpi, pmh, ph, ogh, fh, emr_id)
            cursor.execute(sql_handle)
            sql_handle = \
"UPDATE Examination SET Description='%s' WHERE ID='%s'" %(exam_dscr, emr_id)
            cursor.execute(sql_handle)
            sql_handle = \
"UPDATE Diagnosis SET Description='%s', Sign='%s' WHERE ID='%s'"\
%(dx_dscr, dx_sign, emr_id)
            cursor.execute(sql_handle)
            sql_handle = \
"UPDATE Medical_Advice SET Description='%s', Sign='%s' WHERE ID='%s'"\
%(advice_dscr, advice_sign, emr_id)
            cursor.execute(sql_handle)

            conn.commit()
    else:
        if is_add:
            encd = enc_emr(record)

            name = encd['name']
            sex = encd['sex']
            age = encd['age']
            place = encd['place']
            marital_st = encd['marital_st']
            nation = encd['nation']
            occupation = encd['occupation']
            address = encd['address']
            admission = encd['admission']
            history = encd['history']
            source = encd['source']
            record_date = enc(record_date)
            recorder = enc(op_id)

            cc = encd['cc']

            hpi = encd['hpi']
            pmh = encd['pmh']
            ph = encd['ph']
            ogh = encd['ogh']
            fh = encd['fh']

            exam_dscr = encd['exam_dscr']

            dx_dscr = encd['dx_dscr']
            dx_sign = encd['dx_sign']

            advice_dscr = encd['advice_dscr']
            advice_sign = encd['advice_sign']

            sql_handle = \
"INSERT INTO EMR (ID, CC) VALUES ('%s', '%s')" %(emr_id, cc)
            cursor.execute(sql_handle)
            sql_handle = \
"INSERT INTO Statistic_Info \
(ID, Name, Sex, Age, Permanent_Place, Marital_St, Nation, Occupation, Address, \
Admission_Date, History_Taking_Date, History_Source, Record_Date, Recorder) VALUES \
('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')"\
%(emr_id, name, sex, age, place, marital_st, nation, occupation, address, admission,\
history, source, record_date, recorder)
            cursor.execute(sql_handle)
            sql_handle = \
"INSERT INTO Anamnesis (ID, HPI, PMH, PH, OGH, FH) VALUES \
('%s', '%s', '%s', '%s', '%s', '%s')" %(emr_id, hpi, pmh, ph, ogh, fh)
            cursor.execute(sql_handle)
            sql_handle = \
"INSERT INTO Examination (ID, Description) VALUES ('%s', '%s')" %(emr_id, exam_dscr)
            cursor.execute(sql_handle)
            sql_handle = \
"INSERT INTO Diagnosis (ID, Description, Sign) VALUES ('%s', '%s', '%s')"\
%(emr_id, dx_dscr, dx_sign)
            cursor.execute(sql_handle)
            sql_handle = \
"INSERT INTO Medical_Advice (ID, Description, Sign) VALUES ('%s', '%s', '%s')"\
%(emr_id, advice_dscr, advice_sign)
            cursor.execute(sql_handle)

            conn.commit()
        else:
            error = -1
    cursor.close()
    conn.close()
    if not is_add:
        return (error, record_date)
    return error

# Encrypt the EMR record, return encrypted dictionary as
# {'field': encrypted data, ...}
def enc_emr(record):
    stat = record[1]
    name = enc(stat[0])
    sex = enc(stat[1])
    age = enc(stat[2])
    place = enc(stat[3])
    marital_st = enc(stat[4])
    nation = enc(stat[5])
    occupation = enc(stat[6])
    address = enc(stat[7])
    admission = enc(stat[8])
    history = enc(stat[9])
    source = enc(stat[10])

    cc = enc(record[2])

    anamnesis = record[3]
    hpi = enc(anamnesis[0])
    pmh = enc(anamnesis[1])
    ph = enc(anamnesis[2])
    ogh = enc(anamnesis[3])
    fh = enc(anamnesis[4])

    exam_dscr = enc(record[4])

    dx = record[5]
    dx_dscr = enc(dx[0])
    dx_sign = enc(dx[1])

    advice = record[6]
    advice_dscr = enc(advice[0])
    advice_sign = enc(advice[1])

    return {'name': name,
            'sex': sex,
            'age': age,
            'place': place,
            'marital_st': marital_st,
            'nation': nation,
            'occupation': occupation,
            'address': address,
            'admission': admission,
            'history': history,
            'source': source,
            'cc': cc,
            'hpi': hpi,
            'pmh': pmh,
            'ph': ph,
            'ogh': ogh,
            'fh': fh,
            'exam_dscr': exam_dscr,
            'dx_dscr': dx_dscr,
            'dx_sign': dx_sign,
            'advice_dscr': advice_dscr,
            'advice_sign': advice_sign }

# Functions for op_db()
def is_date(date):
    try:
        datetime.strptime(date, '%Y/%m/%d')
        return True
    except:
        return False

# Legality for EMR fields used in op_db()
def fields_filter(record):
    emr_id = record[0]
    if len(emr_id) != 12:
        return '病历号必须由12个字符组成'

    stat = record[1]
    name = stat[0]
    if len(name) > 20:
        return '姓名长度需要在20之内'
    sex = stat[1]
    if sex != '男' and sex != '女' and sex != '不明':
        return '性别仅允许输入男、女或不明'
    age = stat[2]
    if not age.isdigit():
        return '年龄仅允许输入数字'
    if int(age) < 0 or int(age) > 120:
        return '年龄需要在0到120之间'
    place = stat[3]
    if len(place) > 20:
        return '籍贯长度需要在20之内'
    marital_st = stat[4]
    if marital_st != '' and marital_st != '未婚' and marital_st != '已婚' and marital_st != '丧偶' and marital_st != '离婚':
        return '婚姻仅允许输入未婚、已婚、丧偶或离婚'
    nation = stat[5]
    if len(nation) > 10:
        return '民族长度需要在10之内'
    occupation = stat[6]
    if len(occupation) > 10:
        return '民族长度需要在10之内'
    address = stat[7]
    if len(address) > 50:
        return '住址长度需要在50之内'
    admission = stat[8]
    if not is_date(admission):
        return '入院日期需要符合日期格式：yyyy/MM/dd'
    history = stat[9]
    if history != '' and not is_date(history):
        return '病史采集日期需要符合日期格式：yyyy/MM/dd'
    source = stat[10]
    if len(source) > 20:
        return '病史陈述者长度需要在20之内'

    cc = record[2]
    if len(cc) > 500:
        return '主诉长度需要在500之内'

    anamnesis = record[3]
    hpi = anamnesis[0]
    if len(hpi) > 1000:
        return '现病史长度需要在1000之内'
    pmh = anamnesis[1]
    if len(pmh) > 1000:
        return '既往史长度需要在1000之内'
    ph = anamnesis[2]
    if len(ph) > 1000:
        return '个人史长度需要在1000之内'
    ogh = anamnesis[3]
    if len(ogh) > 1000:
        return '月经婚育史长度需要在1000之内'
    fh = anamnesis[4]
    if len(fh) > 1000:
        return '家族史长度需要在1000之内'

    dscr = record[4]
    if len(dscr) > 9999:
        return '体格检查中的描述长度需要在9999之内'

    dx = record[5]
    dscr = dx[0]
    if len(dscr) > 9999:
        return '诊断中的描述长度需要在9999之内'
    sign = dx[1]
    if len(sign) > 20:
        return '诊断中的医师签名长度需要在20之内'

    advice = record[6]
    dscr = advice[0]
    if len(dscr) > 9999:
        return '医嘱中的描述长度需要在9999之内'
    sign = advice[1]
    if len(sign) > 20:
        return '医嘱中的医师签名长度需要在20之内'

    return False



# Initialize database
#   For permission database
def init_permission_db():
    conn = sql.connect(dir_pdb)
    cursor = conn.cursor()
    sql_handle =\
'CREATE TABLE User (\
ID varchar(30) PRIMARY KEY,\
Name varchar(200),\
Passwd char(60),\
Is_Admin varchar(30)\
)'
    cursor.execute(sql_handle)
    aid = 'admin'
    name = '默认管理员'
    with open(pwdfile, 'r') as passwdf:
        passwd = passwdf.read().strip('\n')
    passwd = tag(passwd)
    is_admin = 'y'
    name = enc(name)
    is_admin = enc(is_admin)

    sql_handle = \
"INSERT INTO User \
(ID, Name, Passwd, Is_Admin) VALUES \
('%s', '%s', '%s', '%s')" %(aid, name, passwd, is_admin)
    cursor.execute(sql_handle)
    conn.commit()
    cursor.close()
    conn.close()

#   For EMR database
def init_emr_db():
    conn = sql.connect(dir_emrdb)
    cursor = conn.cursor()
    # Create the patients statistic information table
    sql_handle =\
'CREATE TABLE Statistic_Info (\
ID char(12) PRIMARY KEY,\
Name varchar(200),\
Sex varchar(50),\
Age varchar(50),\
Permanent_Place varchar(200),\
Marital_St varchar(50),\
Nation varchar(100),\
Occupation varchar(100),\
Address varchar(500),\
Admission_Date varchar(100),\
History_Taking_Date varchar(100),\
History_Source varchar(200),\
Record_Date varchar(100),\
Recorder varchar(200)\
)'
    cursor.execute(sql_handle)
    # Create the anamnesis table
    sql_handle =\
'CREATE TABLE Anamnesis (\
ID char(12) PRIMARY KEY,\
HPI varchar(3000),\
PMH varchar(3000),\
PH varchar(3000),\
OGH varchar(3000),\
FH varchar(3000)\
)'
    cursor.execute(sql_handle)
    # Create the physical examination table
    sql_handle =\
'CREATE TABLE Examination (\
ID char(12) PRIMARY KEY,\
Description varchar(30000)\
)'
    cursor.execute(sql_handle)
    # Create the diagnosis table
    sql_handle =\
'CREATE TABLE Diagnosis (\
ID char(12) PRIMARY KEY,\
Description varchar(30000),\
Sign varchar(200)\
)'
    cursor.execute(sql_handle)
    # Create the medical advice table
    sql_handle =\
'CREATE TABLE Medical_Advice (\
ID char(12) PRIMARY KEY,\
Description varchar(30000),\
Sign varchar(200)\
)'
    cursor.execute(sql_handle)
    # Create the EMR table
    sql_handle =\
'CREATE TABLE EMR (\
ID char(12) PRIMARY KEY,\
CC varchar(1500)\
)'
    cursor.execute(sql_handle)
    conn.commit()
    cursor.close()
    conn.close()

# Initialization from config.ini
config = configparser.ConfigParser()
if os.path.exists(os.path.join(dir, 'config.ini')):
    config.read(os.path.join(dir, 'config.ini'))
else:
    print('Please put the initialization file config.ini into the same \
directory of the software.')
    sys.exit(1)
if 'PORT' in config['DEFAULT']:
    PORT = int(config['DEFAULT']['PORT'])
else:
    PORT = 80
if 'LISTEN' in config['DEFAULT']:
    LISTEN = int(config['DEFAULT']['LISTEN'])
else:
    LISTEN = 100
if 'SETBLOCKING' in config['DEFAULT']:
    SETBLOCKING = int(config['DEFAULT']['SETBLOCKING'])
else:
    SETBLOCKING = 0
if 'KEY_FILE' in config['DEFAULT']:
    KEY_FILE = config['DEFAULT']['KEY_FILE']
else:
    KEY_FILE = 'server_se.key'
if 'PRIVATE_KEY_FILE' in config['DEFAULT']:
    PRIVATE_KEY_FILE = config['DEFAULT']['PRIVATE_KEY_FILE']
else:
    PRIVATE_KEY_FILE = 'server_pke.key'
if 'CERT_FILE' in config['DEFAULT']:
    CERT_FILE = config['DEFAULT']['CERT_FILE']
else:
    CERT_FILE = 'server_cert.pem'
if 'PERMISSION_DB' in config['DEFAULT']:
    PERMISSION_DB = config['DEFAULT']['PERMISSION_DB']
else:
    PERMISSION_DB = 'permissions.db'
if 'EMR_DB' in config['DEFAULT']:
    EMR_DB = config['DEFAULT']['EMR_DB']
else:
    EMR_DB = 'emr.db'
# Load key into memory
if os.path.isabs(KEY_FILE):
    keyfile = KEY_FILE
else:
    keyfile = os.path.join(dir, KEY_FILE)
if not os.path.exists(keyfile):
    key = gen_key(32)
    b64 = b64encode(key).decode('utf-8')
    with open(keyfile, 'w') as keyf:
        keyf.write(b64)
else:
    with open(keyfile, 'r') as keyf:
        b64 = keyf.read().strip().encode('utf-8')
    key = b64decode(b64)
# Allocate the path of permissions database
if os.path.isabs(PERMISSION_DB):
    dir_pdb = PERMISSION_DB
else:
    dir_pdb = os.path.join(dir, PERMISSION_DB)
# Create dirs for permissions database
if not os.path.exists(os.path.dirname(dir_pdb)):
    os.makedirs(os.path.dirname(dir_pdb))
# Create the permissions database if it does not exist
if not os.path.exists(dir_pdb):
    if 'PASSWD_FILE' not in config['DEFAULT']:
        print('Lost password file field "PASSWD_FILE" in config.ini for \
specific default admin\'s password.')
        sys.exit(1)
    else:
        PASSWD_FILE = config['DEFAULT']['PASSWD_FILE']
        if os.path.isabs(PASSWD_FILE):
            pwdfile = PASSWD_FILE
        else:
            pwdfile = os.path.join(dir, PASSWD_FILE)
        if not os.path.exists(pwdfile):
            print('Lost password file for specific default admin\'s password.')
            sys.exit(1)
        else:
            init_permission_db()

# Allocate the path of permissions database
if os.path.isabs(EMR_DB):
    dir_emrdb = EMR_DB
else:
    dir_emrdb = os.path.join(dir, EMR_DB)
# Create dirs for permissions database
if not os.path.exists(os.path.dirname(dir_emrdb)):
    os.makedirs(os.path.dirname(dir_emrdb))
# Create the permissions database if it does not exist
if not os.path.exists(dir_emrdb):
    init_emr_db()


# Initialize context
ctx = SSL.Context(SSL.TLSv1_2_METHOD)
if os.path.isabs(PRIVATE_KEY_FILE):
    ctx.use_privatekey_file(PRIVATE_KEY_FILE)
else:
    ctx.use_privatekey_file(os.path.join(dir, PRIVATE_KEY_FILE))
if os.path.isabs(CERT_FILE):
    ctx.use_certificate_file(CERT_FILE)
else:
    ctx.use_certificate_file(os.path.join(dir, CERT_FILE))
ctx.set_options(SSL.OP_SINGLE_ECDH_USE)
ctx.set_cipher_list('ECDHE+ECDSA+AESGCM:ECDHE+aRSA+AESGCM:\
    !aNULL:!eNULL:!LOW:!MD5:!3DES:!PSK:!DSS:!RC4:!SHA1:!SHA')

# Set up server
server = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
server.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
server.bind(('', int(PORT)))
server.listen(LISTEN)
server.setblocking(SETBLOCKING)

clients = {}
writers = {}
proof = {}
notifications = {}
req_details = {}
med_account = {}
admin_account = {}


def dropClient(cli, errors=None):
    if errors:
        print('Client %s left unexpectedly:' % (clients[cli],))
        print('  ', errors)
    else:
        print('Client %s left politely' % (clients[cli],))
    del clients[cli]
    if cli in writers:
        del writers[cli]
    if cli in med_account:
        del med_account[cli]
    if cli in admin_account:
        del admin_account[cli]
    if not errors:
        cli.shutdown()
    cli.close()


def detectClient(cli):
    if cli not in proof:
        return False
    if proof[cli][0] == cli.master_key():
        if proof[cli][1]:
            return 'admin'
        else:
            return 'med'
    else:
        return False


# Listening non-block programs
while 1:
    try:
        r, w, _ = select.select(
            [server] + list(clients.keys()), list(writers.keys()), []
        )
    except Exception:
        break

#   Read from clients
    for cli in r:
        if cli == server:
            cli, addr = server.accept()
            print('Connection from %s' % (addr,))
            clients[cli] = addr

        else:
            try:
                tmp = cli.recv(1024)
                if cli in notifications:
                    recv_len = len(notifications[cli][1])
                    if notifications[cli][0] <= 1:
                        notifications[cli][1] += tmp
                        recv = notifications[cli][1].decode('utf-8')
                        del notifications[cli]
                    else:
                        notifications[cli][0] -= 1
                        notifications[cli][1] += tmp
                        break
                else:
                    recv = tmp.decode('utf-8')
            except (SSL.WantReadError,
                    SSL.WantWriteError,
                    SSL.WantX509LookupError):
                pass
            except SSL.ZeroReturnError:
                dropClient(cli)
            except SSL.Error as errors:
                dropClient(cli, errors)
            else:
                import traceback
                try:
                    req = json.loads(recv)
                    query = req['req']
                    if query == 'login':
                        if cli in proof:
                            raise Exception
                        Res = login(req)
                        if Res[1] == 0:
                            proof[cli] = (cli.master_key(), True)
                            admin_account[cli] = req['account']
                        elif Res[1] == 1:
                            proof[cli] = (cli.master_key(), False)
                            med_account[cli] = req['account']
                        res = Res[0]
                        if len(res) > 1024:
                            req_details[cli] = res.encode('utf-8')
                            time = math.ceil(len(res)/1024)
                            res = json.dumps({'stat': 'Notify', 'time': time})
                    elif query == 'add_user' or query == 'mod_user':
                        if detectClient(cli) != 'admin':
                            raise Exception
                        record = req['record']
                        if query[:1] == 'a':
                            res = add_user(record)
                        else:
                            res = mod_user(record)
                    elif query == 'notify':
                        if detectClient(cli) != 'med':
                            raise Exception
                        time = math.ceil(req['len']/1024)
                        notifications[cli] = [time, b'']
                        res = json.dumps({'stat': 'Prepared', 'time': time})
                    elif query == 'add_emr' or query == 'mod_emr':
                        if detectClient(cli) != 'med':
                            raise Exception
                        record = req['record']
                        if query[:1] == 'a':
                            res = add_emr(record, med_account[cli])
                        else:
                            res = mod_emr(record, med_account[cli])
                    elif query == 'detail':
                        if detectClient(cli) != 'med':
                            raise Exception
                        emr_id = req['emr_id']
                        record = detail(emr_id, med_account[cli])
                        if record:
                            record = json.dumps(record).encode('utf-8')
                            req_details[cli] = record
                            time = math.ceil(len(record)/1024)
                            res = json.dumps({'stat': 'Accepted', 'time': time})
                        else:
                        # it is that permission denied since
                        # the recorder of the queried EMR is not med_account[cli]
                            res = json.dumps({'stat': 'Unexpected'})
                    elif query == 'del_user':
                        if detectClient(cli) != 'admin':
                            raise Exception
                        aid = req['id']
                        if admin_account[cli] == aid:
                            res = json.dumps({'stat': 'Unexpected'})
                        else:
                            res = del_user(aid)
                    elif query == 'del_emr':
                        if detectClient(cli) != 'med':
                            raise Exception
                        res = del_emr(req['id'])
                    elif query == 'search':
                        permission = detectClient(cli)
                        if not permission:
                            raise Exception
                        type = req['type']
                        keywd = req['keywd'].strip()
                        if permission == 'admin':
                            if type in ('帐号', '姓名'):
                                type = serialize(type)
                                res = json.dumps(search(type, keywd))
                            else:
                                raise Exception
                        else:
                            if type in ('病历号', '姓名', '入院日期', '记录日期'):
                                type = serialize(type)
                                res = json.dumps(search(type, keywd, med_account[cli]))
                            else:
                                raise Exception
                        if len(res) > 1024:
                            req_details[cli] = res.encode('utf-8')
                            time = math.ceil(len(res)/1024)
                            res = json.dumps({'stat': 'Notify', 'time': time})
                except:
                    traceback.print_exc()
                    res = json.dumps({'stat': 'Unexpected'})
                if cli not in writers:
                    writers[cli] = ''
                writers[cli] = writers[cli] + res

#   Write into clients
    for cli in w:
        try:
            case = isinstance(writers[cli], bytes)
            if case:
                ret = cli.send(writers[cli][:1024])
            else:
                ret = cli.send(writers[cli])
        except (SSL.WantReadError,
                SSL.WantWriteError,
                SSL.WantX509LookupError):
            pass
        except SSL.ZeroReturnError:
            dropClient(cli)
        except SSL.Error as errors:
            dropClient(cli, errors)
        else:
            if case:
                case = b''
            else:
                case = ''
            writers[cli] = writers[cli][ret:]
            if writers[cli] == case:
                if cli in req_details:
                    writers[cli] = req_details[cli]
                    del req_details[cli]
                else:
                    del writers[cli]

for cli in clients.keys():
    cli.close()
server.close()
