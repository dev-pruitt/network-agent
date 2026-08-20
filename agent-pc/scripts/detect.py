#!/usr/bin/env python3
"""CPU YOLOv8n person/vehicle detector (onnxruntime). Runtime deps: onnxruntime, numpy, pillow."""
import os, sys, time
import numpy as np
from PIL import Image
import onnxruntime as ort

MODEL = os.path.expanduser("~/network-agent/models/yolov8n.onnx")
IMGSZ = 640
KEEP = {0:"person",1:"bicycle",2:"car",3:"motorcycle",5:"bus",7:"truck"}
CONF = 0.35
IOU  = 0.45
_sess=None
def _session():
    global _sess
    if _sess is None:
        so=ort.SessionOptions(); so.intra_op_num_threads=2
        _sess=ort.InferenceSession(MODEL, sess_options=so, providers=["CPUExecutionProvider"])
    return _sess
def _letterbox(im):
    w,h=im.size; r=min(IMGSZ/w,IMGSZ/h); nw,nh=int(round(w*r)),int(round(h*r))
    canvas=Image.new("RGB",(IMGSZ,IMGSZ),(114,114,114))
    px,py=(IMGSZ-nw)//2,(IMGSZ-nh)//2
    canvas.paste(im.resize((nw,nh),Image.BILINEAR),(px,py))
    return canvas,r,px,py
def _nms(boxes,scores,iou=IOU):
    idx=scores.argsort()[::-1]; keep=[]
    while len(idx):
        i=idx[0]; keep.append(i)
        if len(idx)==1: break
        xx1=np.maximum(boxes[i,0],boxes[idx[1:],0]); yy1=np.maximum(boxes[i,1],boxes[idx[1:],1])
        xx2=np.minimum(boxes[i,2],boxes[idx[1:],2]); yy2=np.minimum(boxes[i,3],boxes[idx[1:],3])
        w=np.maximum(0,xx2-xx1); h=np.maximum(0,yy2-yy1); inter=w*h
        a=(boxes[i,2]-boxes[i,0])*(boxes[i,3]-boxes[i,1])
        b=(boxes[idx[1:],2]-boxes[idx[1:],0])*(boxes[idx[1:],3]-boxes[idx[1:],1])
        iouv=inter/(a+b-inter+1e-9); idx=idx[1:][iouv<iou]
    return keep
def detect(img, min_conf=None):
    """min_conf overrides the module default CONF for this call only.

    Kept as a call-time override rather than a module-level mutable so two
    callers (e.g. a zone-aware caller wanting a lower bar and a plain CLI
    call wanting the default) can never stomp each other's threshold.
    """
    thresh = CONF if min_conf is None else min_conf
    if isinstance(img,str): img=Image.open(img).convert("RGB")
    W,H=img.size; canvas,r,px,py=_letterbox(img)
    x=(np.asarray(canvas,dtype=np.float32)/255.0).transpose(2,0,1)[None]
    out=_session().run(None,{"images":x})[0][0].T
    boxes=out[:,:4]; cls=out[:,4:]; cid=cls.argmax(1); conf=cls.max(1)
    m=(conf>=thresh)&np.isin(cid,list(KEEP.keys()))
    if not m.any(): return []
    b=boxes[m]; conf=conf[m]; cid=cid[m]; xy=np.empty_like(b)
    xy[:,0]=(b[:,0]-b[:,2]/2-px)/r; xy[:,1]=(b[:,1]-b[:,3]/2-py)/r
    xy[:,2]=(b[:,0]+b[:,2]/2-px)/r; xy[:,3]=(b[:,1]+b[:,3]/2-py)/r
    xy[:,[0,2]]=xy[:,[0,2]].clip(0,W); xy[:,[1,3]]=xy[:,[1,3]].clip(0,H)
    keep=_nms(xy,conf)
    return [{"label":KEEP[int(cid[i])],"conf":float(conf[i]),"box":[float(v) for v in xy[i]]} for i in keep]
if __name__=="__main__":
    t=time.time(); r=detect(sys.argv[1]); dt=(time.time()-t)*1000
    print(f"{len(r)} detections in {dt:.0f} ms")
    for d in sorted(r,key=lambda z:-z["conf"]):
        print(f"  {d['label']:10s} {d['conf']*100:4.1f}%  box {[round(v) for v in d['box']]}")
