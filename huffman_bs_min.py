Z = lambda _:[0]*_
GF = lambda:[101342,9667,3497,1072,0,3793,0,0,2815,5235,*Z(3),3570,*Z(3),1383,*Z(3),2970,0,0,2857,*Z(8),1199,*Z(29),1494,1974,*Z(12),1351,*Z(113),1475,*Z(64)]
class N:
    def __init__(s):s.l=s.r=-1;s.p=s.b=s.v=s.f=0
class HuffmanCodec:
    def __init__(s):
        f = GF()
        s.n=[N()for _ in range(511)];
        for i in range(256):s.n[i].f=f[i]
        c=256
        while c<511:
            i=0
            while s.n[i].p!=0:i+=1
            m1=i;i+=1
            while s.n[i].p!=0:i+=1
            m2=i;i+=1
            while i<c:
                if s.n[i].p==0:
                    if s.n[m1].f>s.n[m2].f:
                        if s.n[i].f<s.n[m1].f:m1=i
                    else:
                        if s.n[i].f<s.n[m2].f:m2=i
                i+=1
            s.n[c].f=s.n[m1].f+s.n[m2].f;s.n[m1].p=c-255;s.n[m2].p=c-255;s.n[c].r=m1;s.n[c].l=m2;c+=1
        for i in range(256):
            s.n[i].v=s.n[i].b=0;j=i
            while s.n[j].p!=0:
                p=s.n[j].p+255;s.n[i].v=(s.n[i].v<<1)|(0x01 if s.n[p].r==j else 0);s.n[i].b+=1;j=p
            if s.n[i].b>=8:s.n[i].b=8;s.n[i].v=i<<1
            else:s.n[i].v=(s.n[i].v<<1)|0x01
            s.n[i].b+=1
    def w(s,o,p,v,b):
        i=0
        while i<b:
            j=p//8;k=p%8
            while len(o)<=j:o.append(0)
            if(v>>i)&1:o[j]|=(1<<k)
            p+=1;i+=1
        return p
    def c(s,d):
        if not d:return bytes()
        if d[0]&0x80:raise ValueError("First byte high bit set")
        t=sum(s.n[b].b for b in d);l=(t+7)//8+1;r=t%8
        if l>=len(d):return d
        o=[0];p=8
        for b in d:p=s.w(o,p,s.n[b].v,s.n[b].b)
        o[0]=((8-r%8)if r else 0)|0x80
        return bytes(o)
    def d(s,d):
        if not d:raise ValueError("Empty")
        r=d[0]&0x0F;z=(d[0]>>7)&1
        if not z:return d
        l=(len(d)-1)*8
        if r>l:raise ValueError("Invalid")
        l-=r;o=[];b=0;f=1
        while b<l:
            v=(d[f+b//8]>>(b%8))&1;b+=1
            if v:
                n=510
                while True:
                    v=(d[f+b//8]>>(b%8))&1
                    if v==0:
                        if s.n[n].l==-1:a=n;break
                        else:n=s.n[n].l;b+=1
                    else:
                        if s.n[n].r==-1:a=n;break
                        else:n=s.n[n].r;b+=1
                    if s.n[n].l==-1 and s.n[n].r==-1:a=n;break
                    if b>l:raise ValueError("Overflow")
                o.append(a&0xFF)
            else:
                a=(d[f+b//8]>>(b%8))|(d[f+b//8+1]<<(8-b%8))if b%8!=0 else d[f+b//8];o.append(a&0xFF);b+=8
                if b>l:raise ValueError("Overflow")
        return bytes(o)
    def e(s,d,i=0x7c):return bytes([36,i])+s.c(d)
