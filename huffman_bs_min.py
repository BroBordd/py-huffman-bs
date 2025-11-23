G=[101342,9667,3497,1072,0,3793]+[0]*2+[2815,5235]+[0]*3+[3570]+[0]*2+[1383]+[0]*3+[2970]+[0]*2+[2857]+[0]*8+[1199]+[0]*16+[1494,1974]+[0]*10+[1351]+[0]*129+[1475]+[0]*64
class N:
 def __init__(s):s.l=s.r=s.p=s.b=s.v=s.f=0
class H:
 def __init__(s):s.n=[N()for _ in range(511)];s.build()
 def build(s):
  for i in range(256):s.n[i].f=G[i]
  c=256
  while c<511:
   i=0
   while s.n[i].p:i+=1
   m1=i;i+=1
   while s.n[i].p:i+=1
   m2=i;i+=1
   while i<c:
    if not s.n[i].p:
     if s.n[m1].f>s.n[m2].f:
      if s.n[i].f<s.n[m1].f:m1=i
     elif s.n[i].f<s.n[m2].f:m2=i
    i+=1
   s.n[c].f=s.n[m1].f+s.n[m2].f;s.n[m1].p=c-255;s.n[m2].p=c-255;s.n[c].r=m1;s.n[c].l=m2;c+=1
  for i in range(256):
   s.n[i].v=s.n[i].b=0;x=i
   while s.n[x].p:
    p=s.n[x].p+255
    if s.n[p].r==x:s.n[i].v=(s.n[i].v<<1)|1
    else:s.n[i].v<<=1
    s.n[i].b+=1;x=p
   if s.n[i].b>=8:s.n[i].b=8;s.n[i].v=i<<1
   else:s.n[i].v=(s.n[i].v<<1)|1
   s.n[i].b+=1
 def w(s,o,p,v,vb):
  sb=0
  while sb<vb:
   bi=p//8;bb=p%8
   while len(o)<=bi:o.append(0)
   if(v>>sb)&1:o[bi]|=(1<<bb)
   p+=1;sb+=1
  return p
 def c(s,d):
  if not d:return b''
  if d[0]&128:raise ValueError()
  bc=sum(s.n[b].b for b in d);lo=(bc+7)//8+1;r=bc%8
  if lo>=len(d):return d
  o=[0];p=8
  for b in d:p=s.w(o,p,s.n[b].v,s.n[b].b)
  o[0]=(8-r%8)if r else 0;o[0]|=128
  return bytes(o)
 def d(s,d):
  if not d:raise ValueError()
  r=d[0]&15;z=(d[0]>>7)&1
  if not z:return d
  bl=(len(d)-1)*8
  if r>bl:raise ValueError()
  bl-=r;o=[];b=0;po=1
  while b<bl:
   bv=(d[po+b//8]>>(b%8))&1;b+=1
   if bv:
    n=510
    while True:
     bv=(d[po+b//8]>>(b%8))&1
     if not bv:
      if s.n[n].l==-1:v=n;break
      n=s.n[n].l;b+=1
     else:
      if s.n[n].r==-1:v=n;break
      n=s.n[n].r;b+=1
     if s.n[n].l==-1 and s.n[n].r==-1:v=n;break
     if b>bl:raise ValueError()
    o.append(v&255)
   else:
    if b%8==0:v=d[po+b//8]
    else:v=(d[po+b//8]>>(b%8))|(d[po+b//8+1]<<(8-b%8))
    o.append(v&255);b+=8
    if b>bl:raise ValueError()
  return bytes(o)
 def e(s,d,c=124):return bytes([36,c])+s.c(d)
def dec(h):d=bytes.fromhex(h.replace(' ',''));return H().d(d[2:])
def enc(h,c=124):return H().e(bytes.fromhex(h.replace(' ','')),c)
