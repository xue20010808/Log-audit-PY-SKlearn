import re
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn import neighbors
from sklearn import metrics
from sklearn import svm
from sklearn import tree
import pydot
from sklearn.tree import export_graphviz
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
import os
import time
def ordP(str):
    sum=0
    for i in str.strip():
        sum=sum+ord(i)
    return sum
os.environ['PATH']=os.environ['PATH'] + (';c:\\Program Files\\Graphviz\\bin\\')
f=open(r'C:\Users\薛磊\Documents\Tencent Files\1819063768\FileRecv\auth.log.txt')
txt=f.read()
obj=re.compile(r'Invalid user(?P<user>.*?)from(?P<ip>.*?)port.*?',re.S)
iobj=re.compile(r'\d+\.\d+\.\d+\.\d+',re.S)
aobj=re.compile((r'Accepted password for(?P<name>.*?)from(?P<aip>.*?)port.*?'),re.S)
info=aobj.finditer(txt)
legaluser=[]
tianqing=[]
gujun=[]
ubuntu=[]
wenxuezhi=[]
fangwei=[]
zhongshuiming=[]
yanleiming=[]
zhaoxiaoping=[]
xionglizhi=[]
alluserip=[]
accepeddic={}

for i in info:

    if i.group('aip') not in alluserip:
        alluserip.append(i.group('aip').strip())
    if i.group('name') not in legaluser:
        legaluser.append(i.group('name'))
    if i.group('name').strip()=='tianqing':
        if i.group('aip') not in tianqing:
            tianqing.append(i.group('aip'))
    if i.group('name').strip()=='gujun':
        if i.group('aip') not in gujun:
            gujun.append(i.group('aip'))
    if i.group('name').strip()=='ubuntu':
        if i.group('aip') not in ubuntu:
            ubuntu.append(i.group('aip'))
    if i.group('name').strip()=='ubuntu':
        if i.group('aip') not in ubuntu:
            ubuntu.append(i.group('aip'))
    if i.group('name').strip()=='wenxuezhi':
        if i.group('aip') not in wenxuezhi:
            wenxuezhi.append(i.group('aip'))
    if i.group('name').strip()=='fangwei':
        if i.group('aip') not in fangwei:
            fangwei.append(i.group('aip'))
    if i.group('name').strip()=='zhongshuiming':
        if i.group('aip') not in zhongshuiming:
            zhongshuiming.append(i.group('aip'))
    if i.group('name').strip()=='yanleiming':
        if i.group('aip') not in yanleiming:
            yanleiming.append(i.group('aip'))
    if i.group('name').strip()=='zhaoxiaoping':
        if i.group('aip') not in zhaoxiaoping:
            zhaoxiaoping.append(i.group('aip'))
    if i.group('name').strip()=='xionglizhi':
        if i.group('aip') not in xionglizhi:
            xionglizhi.append(i.group('aip'))
info2=aobj.finditer(txt)
for i in legaluser:
    accepeddic.update({i.strip():0})

for i in info2:
    accepeddic[i.group('name').strip()]+=1
print(accepeddic)
print(legaluser)
print('tianqing 使用过的ip:',tianqing)
print('gujun 使用过的ip:',gujun)
print('ubuntu 使用过的ip:',ubuntu)
print('wenxuezhi 使用过的ip',wenxuezhi)
print('xionglizhi 使用过的ip:',xionglizhi)
print('fangwei 使用过的ip：',fangwei)
print('zhongshuiming 使用过的ip：',zhongshuiming)
print('yanleiming使用过的ip:',yanleiming)
print('zhaoxiaoping 使用过的ip:',zhaoxiaoping)
print(alluserip)
res=obj.finditer(txt)
finding=iobj.findall(txt)
allip=[]
for i in finding:
    if i not in allip:
        allip.append(i)

iplist=[]
attacker1=[]
for i in res:

    if i.group('ip')==' 10.255.249.161 ':
        if i.group('user') not in attacker1:
            attacker1.append(i.group('user'))
    if i.group('ip') not in iplist:
        iplist.append(i.group('ip'))

print('可疑非法用户ip：',iplist)
print('所有ip:',allip)
print(attacker1)
for i in allip:
    if i not in alluserip:
        print(i)
fobj=re.compile(r'Failed password for(?P<Name>.*?) from.*?',re.S)
lo=fobj.finditer(txt)
fname=[]
for i in lo :

       fname.append(i.group('Name'))
for i in range(0,len(fname)):
    fname[i]=fname[i].split(' ')[-1]
    if fname[i]=='tianqin':
        fname[i]=='tianqing'
dic={}
for i in fname:
    if i not in attacker1:
        attacker1.append(i)
for i in attacker1 :
    dic.update({f'{i.strip()}':0})
for i in legaluser:
    dic.update({f'{i.strip()}':0})
print(fname)


for i in fname:

    dic[f'{i}']=dic[f'{i}']+1
print(dic)
portnumlist=[]
alist=attacker1+legaluser
print(len(alist))
for j in alist:
 if '?' in j:
   portnumlist.append(0)
   continue
 pobj=re.compile(rf'{j.strip()} from \d+\.\d+\.\d+\.\d+ port(?P<port>.*?)ssh2',re.S)
 pres=pobj.finditer(txt)
 fport=[]
 for i in pres:
  fport.append(i.group('port').strip().split('\n')[0])
 portnumlist.append(len(fport))
print(portnumlist)
x_mat = np.zeros((len(alist), 5))
rank=0
print(dic)
print(len(attacker1))
for i in x_mat:
    i[0]=ordP(alist[rank])
    if rank>5756:
        i[1]=accepeddic[legaluser[rank-5757].strip()]

    if alist[rank].strip() in fname:
        i[2]=dic[alist[rank].strip()]
    i[3]=portnumlist[rank]

    if rank<=5756:
        i[4]=1

    rank=rank+1
y_label=[]
for i in x_mat:
    y_label.append(i[4])
print(x_mat[-1])
print(x_mat[0:50])
print(x_mat.shape)
y = []
for n in y_label:
    y.append(int(n))
y = np.array(y, dtype = int)
print(y)
train_data, test_data, train_target, test_target = train_test_split(x_mat, y, test_size=0.5, random_state=8)
print (train_data.shape, train_target.shape)
print (test_data.shape, test_target.shape)
time1=time.time()
#clf=neighbors.KNeighborsClassifier(n_neighbors=6)
#clf.fit(train_data[:,(0,2,3)],train_target)
#result=clf.predict(test_data[:,(0,2,3)])
#clf=svm.OneClassSVM(nu=0.9, kernel="rbf", gamma=0.1)
#clf.fit(train_data,train_target)
#clf=tree.DecisionTreeClassifier(max_depth=4,random_state=234)
#print(train_data)
#clf=MultinomialNB(alpha=0.05)
#clf=LogisticRegression(penalty='l2')
clf = RandomForestClassifier(n_estimators=8)
clf.fit(train_data[:,(0,2,3)],train_target)
result=clf.predict(test_data[:,(0,2,3)])
print (sum(result==test_target))
print(metrics.classification_report(test_target, result))
#feature_names=['username','failed password nums','including port nums']
#export_graphviz(clf,out_file="tree.dot",class_names=['legaluser','inruder'],feature_names=feature_names,rounded=True,filled=True)
#(graph,) = pydot.graph_from_dot_file('tree.dot')
#graph.write_png(r'C:\Users\薛磊\Desktop\tree.png')
time2=time.time()
print(time2-time1)
