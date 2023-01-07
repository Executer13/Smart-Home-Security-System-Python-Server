from glob import glob

from multiprocessing.connection import Listener
import os
import shutil
import threading
from statistics import mode
import sys
from tkinter import *
import ctypes
import time
import numpy as np
from numpy import linalg as LA, true_divide
import cv2
from scipy.spatial import distance
from munkres import Munkres              
from openvino.runtime import Core
from line_boundary_check import *
import pyrebase
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from datetime import datetime
from datetime import date
import requests
import json
import ast
import tkinter.messagebox as tkMessageBox
from threading import Thread
import logging as log
import webbrowser
import time
import imutils
temp=''
eml=''
intMode=0
time_function_done= time.time()-3
cap=''
# FIREBASE AREA
firebaseConfig = {




  "apiKey": "AIzaSyD-Ovh6Qg_YNIqwHebN5JrefZGanuGcUoU",
  "authDomain": "smart-home-security-823d8.firebaseapp.com",
  "databaseURL": "https://smart-home-security-823d8-default-rtdb.firebaseio.com",
  "projectId": "smart-home-security-823d8",
  "storageBucket": "smart-home-security-823d8.appspot.com",
  "messagingSenderId": "581039040412",
  "appId": "1:581039040412:web:c22bf9b3f89c5c01ee4a59",
  "measurementId": "G-VM71JZK988",
  "serviceAccount":"smart-home-security-823d8-firebase-adminsdk-w4mv6-519d8f50ad.json"
}







#------------------------------------
# Area intrusion detection
class area:
    def __init__(self, contour):
        self.contour  = np.array(contour, dtype=np.int32)
        self.countx    = 0

warning_obj = None




# initializations 
cred = credentials.Certificate('smart-home-security-823d8-firebase-adminsdk-w4mv6-519d8f50ad.json')
firebase_admin.initialize_app(cred)
db = firestore.client()
serverToken = 'AAAAh0igJ5w:APA91bEiodHAwhj36W_aHpvCgeIvphjrDt2cWojoVquRrx-rWB-bXOWuSocxTCeo90xqmbYWXcPwt4fvFdpm62eyESEEQXmGLMv1dnDmgkPvZmlwjnGZvF4NyUMNlQ6mz-OR5r-s4xBJ'
deviceToken = 'null'
IntPoints = ''
mode=1
tr=0
firebase=pyrebase.initialize_app(firebaseConfig)
auth=firebase.auth()
storage=firebase.storage()
areas = '1'
rtsp=0

class boundaryLine:
    def __init__(self, line=(0,0,0,0)):
        self.p0 = (line[0], line[1])
        self.p1 = (line[2], line[3])
        self.color = (255,255,0)
        self.lineThinkness = 4
        self.textColor = (0,255,255)
        self.textSize = 4
        self.textThinkness = 2
        self.count1 = 0
        self.count2 = 0

# Draw single boundary line
def drawBoundaryLine(img, line):
    x1, y1 = line.p0
    x2, y2 = line.p1
    cv2.line(img, (x1, y1), (x2, y2), line.color, line.lineThinkness)
    cv2.putText(img, str(line.count1), (x1, y1), cv2.FONT_HERSHEY_PLAIN, line.textSize, line.textColor, line.textThinkness)
    cv2.putText(img, str(line.count2), (x2, y2), cv2.FONT_HERSHEY_PLAIN, line.textSize, line.textColor, line.textThinkness)
    cv2.drawMarker(img, (x1, y1),line.color, cv2.MARKER_TRIANGLE_UP, 16, 4)
    cv2.drawMarker(img, (x2, y2),line.color, cv2.MARKER_TILTED_CROSS, 16, 4)

# Draw multiple boundary lines
def drawBoundaryLines(img, boundaryLines):
    for line in boundaryLines:
        drawBoundaryLine(img, line)


def uploadCapture(frames,text):
    global deviceToken
    print(deviceToken)
    now = datetime.now()
            #9:17:45.44343
    today = date.today()
            
    current_time = now.strftime("%H-%M-%S")
   
    str="{} {} Capture.jpg"
    sk=str.format(today,current_time)
    cv2.imwrite(sk, frames)

    str="{} {} Capture.jpg"
    sk=str.format(today,current_time)

    storage.child('Captures/'+sk).put(sk)

    link=storage.child('Captures/'+sk).get_url(None)
    str="{} {}"
    cap_name=str.format(today,current_time)

    doc_ref = db.collection('DB').document(auth.current_user['localId']).collection('Captures').document(cap_name)
    
    current_time = now.strftime("%H:%M:%S")
    upload_t="{}"
    upload_time=upload_t.format(current_time)
    upload_d="{}"
    upload_date=upload_d.format(today)


    doc_ref.set({
        'Name':text,
        'Date':upload_date,
        'Time':upload_time,
        'Link':link,
    
        })
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'key=' + serverToken,
      }

    body = {
          'notification': {'title': text,
                            'body': 'New Notification'
                            },
          'to':
              deviceToken,
          'priority': 'high',
        #   'data': dataPayLoad,
        }
    response = requests.post("https://fcm.googleapis.com/fcm/send",headers = headers, data=json.dumps(body))
    print(response.status_code)
    print(response.json())   
    print("capture uploaded as ",sk)


def checkLineCross(boundary_line, trajectory,frames):
    traj_p0  = (trajectory[0], trajectory[1])    # Trajectory of an object
    traj_p1  = (trajectory[2], trajectory[3])
    bLine_p0 = (boundary_line.p0[0], boundary_line.p0[1]) # Boundary line
    bLine_p1 = (boundary_line.p1[0], boundary_line.p1[1])
    intersect = checkIntersect(traj_p0, traj_p1, bLine_p0, bLine_p1)      # Check if intersect or not
    if intersect == True:
         
         global time_function_done
         if (time_function_done + 2) < time.time():
                time_function_done = time.time()
                Thread(target=uploadCapture, args=(frames,'Intrusion Deteted at Home!!' )).start()   

         angle = calcVectorAngle(traj_p0, traj_p1, bLine_p0, bLine_p1)   # Calculate angle between trajectory and boundary line
         if angle<180:
            boundary_line.count1 += 1
            
         else:
            boundary_line.count2 += 1
           
        #cx, cy = calcIntersectPoint(traj_p0, traj_p1, bLine_p0, bLine_p1) # Calculate the intersect coordination

# Multiple lines cross check
def checkLineCrosses(boundaryLines, objects,frames):
    for obj in objects:
        traj = obj.trajectory
        if len(traj)>1:
            p0 = traj[-2]
            p1 = traj[-1]
            for line in boundaryLines:
                checkLineCross(line, [p0[0],p0[1], p1[0],p1[1]],frames)




# Area intrusion check
def checkAreaIntrusion(areas, objects,frames):
    
    for area in areas:
        area.countx = 0
        for obj in objects:
            p0 = (obj.pos[0]+obj.pos[2])/2
            p1 = (obj.pos[1]+obj.pos[3])/2
            if cv2.pointPolygonTest(area.contour, (p0, p1), False)>=0:
            
                area.countx += 1
                global time_function_done
                if (time_function_done + 2) < time.time():
                     time_function_done = time.time()
                     Thread(target=uploadCapture, args=(frames,'Intrusion Deteted at Home!!' )).start()
 
          

# Draw areas (polygons)
def drawAreas(img, areas):
    for area in areas:
        if area.countx>0:
            color=(0,0,255)
        else:
            color=(255,0,0)
        cv2.polylines(img, [area.contour], True, color,4)
        cv2.putText(img, str(area.countx), (area.contour[0][0], area.contour[0][1]), cv2.FONT_HERSHEY_PLAIN, 4, color, 2)


#------------------------------------
# Object tracking

class object:
    def __init__(self, pos, feature, id=-1):
        self.feature = feature
        self.id = id
        self.trajectory = []
        self.time = time.monotonic()
        self.pos = pos

class objectTracker:
    def __init__(self):
        self.objectid = 0
        self.timeout  = 3   # sec
        self.clearDB()
        self.similarityThreshold = 0.4
        pass

    def clearDB(self):
        self.objectDB = []

    def evictTimeoutObjectFromDB(self):
        # discard time out objects
        now = time.monotonic()
        for object in self.objectDB:
            if object.time + self.timeout < now:
                self.objectDB.remove(object)     # discard feature vector from DB
                print("Discarded  : id {}".format(object.id))

    # objects = list of object class
    def trackObjects(self, objects):
        # if no object found, skip the rest of processing
        if len(objects) == 0:
            return

        # If any object is registred in the db, assign registerd ID to the most similar object in the current image
        if len(self.objectDB)>0:
            # Create a matix of cosine distance
            cos_sim_matrix=[ [ distance.cosine(objects[j].feature, self.objectDB[i].feature) 
                            for j in range(len(objects))] for i in range(len(self.objectDB)) ]
            # solve feature matching problem by Hungarian assignment algorithm
            hangarian = Munkres()
            combination = hangarian.compute(cos_sim_matrix)

            # assign ID to the object pairs based on assignment matrix
            for dbIdx, objIdx in combination:
                if distance.cosine(objects[objIdx].feature, self.objectDB[dbIdx].feature)<self.similarityThreshold:
                    objects[objIdx].id = self.objectDB[dbIdx].id                               # assign an ID
                    self.objectDB[dbIdx].feature = objects[objIdx].feature                     # update the feature vector in DB with the latest vector (to make tracking easier)
                    self.objectDB[dbIdx].time    = time.monotonic()                            # update last found time
                    xmin, ymin, xmax, ymax = objects[objIdx].pos
                    self.objectDB[dbIdx].trajectory.append([(xmin+xmax)//2, (ymin+ymax)//2])   # record position history as trajectory
                    objects[objIdx].trajectory = self.objectDB[dbIdx].trajectory

        # Register the new objects which has no ID yet
        for obj in objects:
            if obj.id==-1:           # no similar objects is registred in feature_db
                obj.id = self.objectid
                self.objectDB.append(obj)  # register a new feature to the db
                self.objectDB[-1].time = time.monotonic()
                xmin, ymin, xmax, ymax = obj.pos
                self.objectDB[-1].trajectory = [[(xmin+xmax)//2, (ymin+ymax)//2]]  # position history for trajectory line
                obj.trajectory = self.objectDB[-1].trajectory
                self.objectid+=1

    def drawTrajectory(self, img, objects):
        for obj in objects:
            if len(obj.trajectory)>1:
                cv2.polylines(img, np.array([obj.trajectory], np.int32), False, (0,0,0), 4)



#------------------------------------


# DL models for pedestrian detection and person re-identification

# boundary lines
boundaryLines=''




# Areas
#areas = [
 #   area([ [139.33333333333334, 179.0], [150.66666666666666, 388.3333333333333], [303.0, 363.3333333333333],[ 286.6666666666667, 192.0],[ 145.0, 184.0] ])
#]
#area(list(map(list, d.items())))
#areas=[area]


_N, _C, _H, _W = 0, 1, 2, 3

def resizeAndPad(img, size, padColor=255):

    h, w = img.shape[:2]
    sh, sw = size

    # interpolation method
    if h > sh or w > sw: # shrinking image
        interp = cv2.INTER_AREA

    else: # stretching image
        interp = cv2.INTER_CUBIC

    # aspect ratio of image
    aspect = float(w)/h 
    saspect = float(sw)/sh

    if (saspect > aspect) or ((saspect == 1) and (aspect <= 1)):  # new horizontal image
        new_h = sh
        new_w = np.round(new_h * aspect).astype(int)
        pad_horz = float(sw - new_w) / 2
        pad_left, pad_right = np.floor(pad_horz).astype(int), np.ceil(pad_horz).astype(int)
        pad_top, pad_bot = 0, 0

    elif (saspect < aspect) or ((saspect == 1) and (aspect >= 1)):  # new vertical image
        new_w = sw
        new_h = np.round(float(new_w) / aspect).astype(int)
        pad_vert = float(sh - new_h) / 2
        pad_top, pad_bot = np.floor(pad_vert).astype(int), np.ceil(pad_vert).astype(int)
        pad_left, pad_right = 0, 0

    # set pad color
    if len(img.shape) is 3 and not isinstance(padColor, (list, tuple, np.ndarray)): # color image but only one color provided
        padColor = [padColor]*3

    # scale and pad
    scaled_img = cv2.resize(img, (new_w, new_h), interpolation=interp)
    scaled_img = cv2.copyMakeBorder(scaled_img, pad_top, pad_bot, pad_left, pad_right, borderType=cv2.BORDER_CONSTANT, value=padColor)

    return scaled_img



 
class thread_with_exception(threading.Thread):
    def __init__(self, name):
        threading.Thread.__init__(self)
        self.name = name
             
    def run(self):
 
        # target function of the thread class
        try:
            while True:
                if self.name=='Thread 1':
                             detector(areas)
                else:
                             fmain()                                
        finally:
            print('ended')
          
    def get_id(self):
 
        # returns id of the respective thread
        if hasattr(self, '_thread_id'):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id
  
    def raise_exception(self):
        
        thread_id = self.get_id()
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id,
              ctypes.py_object(SystemExit))
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            print('Exception raise failure')
      










class FreshestFrame(thread_with_exception):
    def __init__(self, capture, name='FreshestFrame'):
        self.capture = capture
        assert self.capture.isOpened()

        # this lets the read() method block until there's a new frame
        self.cond = threading.Condition()

        # this allows us to stop the thread gracefully
        self.running = False

        # keeping the newest frame around
        self.frame = None

        # passing a sequence number allows read() to NOT block
        # if the currently available one is exactly the one you ask for
        self.latestnum = 0

        # this is just for demo purposes		
        self.callback = None
        
        super().__init__(name=name)
        self.start()

    def start(self):
        self.running = True
        super().start()

    def release(self, timeout=None):
        self.running = False
        self.join(timeout=timeout)
        self.capture.release()

    def run(self):
        counter = 0
        while self.running:
            # block for fresh frame
            (rv, img) = self.capture.read()
            assert rv
            counter += 1

            # publish the frame
            with self.cond: # lock the condition for this operation
                self.frame = img if rv else None
                self.latestnum = counter
                self.cond.notify_all()

            if self.callback:
                self.callback(img)

    def read(self, wait=True, seqnumber=None, timeout=None):
        # with no arguments (wait=True), it always blocks for a fresh frame
        # with wait=False it returns the current frame immediately (polling)
        # with a seqnumber, it blocks until that frame is available (or no wait at all)
        # with timeout argument, may return an earlier frame;
        #   may even be (0,None) if nothing received yet

        with self.cond:
            if wait:
                if seqnumber is None:
                    seqnumber = self.latestnum+1
                if seqnumber < 1:
                    seqnumber = 1
                
                rv = self.cond.wait_for(lambda: self.latestnum >= seqnumber, timeout=timeout)
                if not rv:
                    return (self.latestnum, self.frame)

            return (self.latestnum, self.frame)

























        # 1,3,384,672 -> 1,1,200,7
        # 1,3,256,128 -> 1,256

model_detector  = 'intel/pedestrian-detection-adas-0002/FP16/pedestrian-detection-adas-0002'
model_reidentifier = 'intel/person-reidentification-retail-0277/FP16/person-reidentification-retail-0277'

# Open USB webcams (or a movie file)
'''
cap = cv2.VideoCapture(0)

'''
infile = 'people.mp4'



#'''



core = Core()


# Prep for face/pedestrian detection
model_detector  = core.read_model(model_detector+'.xml')                           # model=pedestrian-detection-adas-0002
model_detector_shape = model_detector.input().get_shape()
compiled_model_detector    = core.compile_model(model_detector, 'CPU')
#compiled_model_det    = core.compile_model(model_det, 'GPU', gpu_config)
ireq_model_detector = compiled_model_detector.create_infer_request()

# Preparation for face/pedestrian re-identification
model_reidentifier = core.read_model(model_reidentifier+'.xml')                          # person-reidentificaton-retail-0079
model_reidentifier_shape = model_reidentifier.input().get_shape()
compiled_model_reidentifier    = core.compile_model(model_reidentifier, 'CPU')

#compiled_model_reid    = core.compile_model(model_reid, 'GPU', gpu_config)
ireq_reid = compiled_model_reidentifier.create_infer_request()

tracker = objectTracker()
















def all(image):
    
   
    image=resizeAndPad(image,(360,780),127)
    inBlob = cv2.resize(image, (model_detector_shape[3], model_detector_shape[2]))
    inBlob = inBlob.transpose((2,0,1))
    inBlob = inBlob.reshape(list(model_detector_shape))
   
    # Either one of following way is OK.
    detObj = ireq_model_detector.get_tensor('detection_out').data.reshape((200,7)) 
    #detObj = ireq_det.get_tensor(compiled_model_det.output(0)).data.reshape((200,7))

    objects = []
    for obj in detObj:                # obj = [ image_id, label, conf, xmin, ymin, xmax, ymax ]
        if obj[2] > 0.75:             # Confidence > 75% 
            xmin = abs(int(obj[3] * image.shape[1]))
            ymin = abs(int(obj[4] * image.shape[0]))
            xmax = abs(int(obj[5] * image.shape[1]))
            ymax = abs(int(obj[6] * image.shape[0]))
            class_id = int(obj[1])

            obj_img=image[ymin:ymax,xmin:xmax].copy()             # Crop the found object

            # Obtain feature vector of the detected object using re-identification model
            inBlob = cv2.resize(obj_img, (model_reidentifier_shape[3], model_reidentifier_shape[2]))
            inBlob = inBlob.transpose((2,0,1))
            inBlob = inBlob.reshape(model_reidentifier_shape)
            
            featVec = ireq_reid.get_tensor(compiled_model_reidentifier.output(0)).data.ravel()
            objects.append(object([xmin,ymin, xmax,ymax], featVec, -1))

    outimg = image.copy()

    tracker.trackObjects(objects)
    tracker.evictTimeoutObjectFromDB()
    

    
    # Draw bounding boxes, IDs and trajectory
    for obj in objects:
        id = obj.id
        color = ( (((~id)<<6) & 0x100)-1, (((~id)<<7) & 0x0100)-1, (((~id)<<8) & 0x0100)-1 )
        xmin, ymin, xmax, ymax = obj.pos
        cv2.rectangle(outimg, (xmin+10, ymin-10), (xmax, ymax), color, 2)
        cv2.putText(outimg, 'ID='+str(id), (xmin, ymin - 7), cv2.FONT_HERSHEY_COMPLEX, 1.0, color, 1)
    #outimg = cv2.rotate(outimg, cv2.ROTATE_90_COUNTERCLOCKWISE)
    #outimg=resizeAndPad(outimg,(780,360),127)
    if intMode==0:
            
            drawBoundaryLines(outimg, boundaryLines)
            checkLineCrosses(boundaryLines, objects,outimg)
    else:
            
            checkAreaIntrusion(areas, objects,outimg)
            drawAreas(outimg, areas)
    return outimg         
            
    




def main():
    # these windows belong to the main thread
    cv2.namedWindow("frame")
    # on win32, imshow from another thread to this DOES work
    cv2.namedWindow("realtime")

    # open some camera
    cap = cv2.VideoCapture(rtsp)
    cap.set(cv2.CAP_PROP_FPS, 30)

    global fresh 
    fresh = FreshestFrame(cap)
    
    

    # a way to watch the camera unthrottled
    def callback(img):
        cv2.imshow("realtime", img)
        # main thread owns windows, does waitkey

    fresh.callback = callback

    # main loop
    # get freshest frame, but never the same one twice (cnt increases)
    # see read() for details
    cnt = 0
    while True:
        # test that this really takes NO time
        # (if it does, the camera is actually slower than this loop and we have to wait!)
        t0 = time.perf_counter()
        cnt,img = fresh.read(seqnumber=cnt+1)
        dt = time.perf_counter() - t0
        if dt > 0.010: # 10 milliseconds
            print("NOTICE: read() took {dt:.3f} secs".format(dt=dt))

        # let's pretend we need some time to process this frame
        img=all(img)

        cv2.imshow("frame", img)
        # this keeps both imshow windows updated during the wait (in particular the "realtime" one)
        key = cv2.waitKey(1)
        if key == 27:
            break

        print("done!")

    fresh.release()
    
    cv2.destroyWindow("frame")
    cv2.destroyWindow("realtime")


    


def detector(d):
    
    
    global boundaryLines,areas,cap
          # 1,3,384,672 -> 1,1,200,7
          # 1,3,256,128 -> 1,256
    
    model_detector  = 'intel/pedestrian-detection-adas-0002/FP16/pedestrian-detection-adas-0002'
    model_reidentifier = 'intel/person-reidentification-retail-0277/FP16/person-reidentification-retail-0277'

    # Open USB webcams (or a movie file)
    '''
    
    
    '''
    infile = 'people.mp4'
   
   
    
    #'''
    
    

    core = Core()

   
    # Prep for face/pedestrian detection
    model_detector  = core.read_model(model_detector+'.xml')                           # model=pedestrian-detection-adas-0002
    model_detector_shape = model_detector.input().get_shape()
    compiled_model_detector    = core.compile_model(model_detector, 'CPU')
    #compiled_model_det    = core.compile_model(model_det, 'GPU', gpu_config)
    ireq_model_detector = compiled_model_detector.create_infer_request()
    
    # Preparation for face/pedestrian re-identification
    model_reidentifier = core.read_model(model_reidentifier+'.xml')                          # person-reidentificaton-retail-0079
    model_reidentifier_shape = model_reidentifier.input().get_shape()
    compiled_model_reidentifier   = core.compile_model(model_reidentifier, 'CPU')
    
    #compiled_model_reid    = core.compile_model(model_reid, 'GPU', gpu_config)
    ireq_model_reidentifier = compiled_model_reidentifier.create_infer_request()
   
    tracker = objectTracker()
    

    global cap 
    cap= cv2.VideoCapture(rtsp)
    cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 360)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 780)
    cap.set(cv2.CAP_PROP_FPS, 30)
    cap.set(cv2.CAP_PROP_AUTOFOCUS, 1)
    cap.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*'MJPG'))
    





    try:
        while cv2.waitKey(1)!=27: 
            
            cap.grab()         
            ret, image = cap.read()
            
            
            if ret==False:
                del cap
                cap = cv2.VideoCapture(rtsp)
                continue
            
            image=resizeAndPad(image,(360,780),127)
            inBlob = cv2.resize(image, (model_detector_shape[3], model_detector_shape[2]))
            inBlob = inBlob.transpose((2,0,1))
            inBlob = inBlob.reshape(list(model_detector_shape))
            res = ireq_model_detector.infer({0: inBlob})
            # Either one of following way is OK.
            detObj = ireq_model_detector.get_tensor('detection_out').data.reshape((200,7)) 
            #detObj = ireq_det.get_tensor(compiled_model_det.output(0)).data.reshape((200,7))
   
            objects = []
            for obj in detObj:                # obj = [ image_id, label, conf, xmin, ymin, xmax, ymax ]
                if obj[2] > 0.65:             # Confidence > 75% 
                    xmin = abs(int(obj[3] * image.shape[1]))
                    ymin = abs(int(obj[4] * image.shape[0]))
                    xmax = abs(int(obj[5] * image.shape[1]))
                    ymax = abs(int(obj[6] * image.shape[0]))
                    class_id = int(obj[1])

                    obj_img=image[ymin:ymax,xmin:xmax].copy()             # Crop the found object

                    # Obtain feature vector of the detected object using re-identification model
                    inBlob = cv2.resize(obj_img, (model_reidentifier_shape[3], model_reidentifier_shape[2]))
                    inBlob = inBlob.transpose((2,0,1))
                    inBlob = inBlob.reshape(model_reidentifier_shape)
                    res = ireq_model_reidentifier.infer({0: inBlob})
                    featVec = ireq_model_reidentifier.get_tensor(compiled_model_reidentifier.output(0)).data.ravel()
                    objects.append(object([xmin,ymin, xmax,ymax], featVec, -1))

            outimg = image.copy()

            tracker.trackObjects(objects)
            tracker.evictTimeoutObjectFromDB()
            

            
            # Draw bounding boxes, IDs and trajectory
            for obj in objects:
                id = obj.id
                color = ( (((~id)<<6) & 0x100)-1, (((~id)<<7) & 0x0100)-1, (((~id)<<8) & 0x0100)-1 )
                xmin, ymin, xmax, ymax = obj.pos
                cv2.rectangle(outimg, (xmin+10, ymin-10), (xmax, ymax), color, 2)
                cv2.putText(outimg, 'ID='+str(id), (xmin, ymin - 7), cv2.FONT_HERSHEY_COMPLEX, 1.0, color, 1)
            
            
            if intMode==0:
                    
                    drawBoundaryLines(outimg, boundaryLines)
                    checkLineCrosses(boundaryLines, objects,outimg)
            else:
                    
                    checkAreaIntrusion(areas, objects,outimg)
                    drawAreas(outimg, areas)
            cv2.imshow('image', outimg)
    except KeyboardInterrupt:
        pass

    cv2.destroyAllWindows()
    





















































# face identifier  
import sys
import cv2
import numpy as np
from pathlib import Path
#sys.path.append(str(Path(__file__).resolve().parents[2] ))
#from window import serverToken,deviceToken,IntPoints
from utils import cut_rois, resize_input
from ie_module import Module


class FaceIdentifier(Module):
    # Taken from the description of the model:
    # intel_models/face-reidentification-retail-0095
    REFERENCE_LANDMARKS = [
        (30.2946 / 96, 51.6963 / 112), # left eye
        (65.5318 / 96, 51.5014 / 112), # right eye
        (48.0252 / 96, 71.7366 / 112), # nose tip
        (33.5493 / 96, 92.3655 / 112), # left lip corner
        (62.7299 / 96, 92.2041 / 112)] # right lip corner

    UNKNOWN_ID = -1
    UNKNOWN_ID_LABEL = "Unknown"

    class Result:
        def __init__(self, id, distance, desc):
            self.id = id
            self.distance = distance
            self.descriptor = desc

    def __init__(self, core, model, match_threshold=0.5, match_algo='HUNGARIAN'):
        super(FaceIdentifier, self).__init__(core, model, 'Face Reidentification')

        if len(self.model.inputs) != 1:
            raise RuntimeError("The model expects 1 input layer")
        if len(self.model.outputs) != 1:
            raise RuntimeError("The model expects 1 output layer")

        self.input_tensor_name = self.model.inputs[0].get_any_name()
        self.input_shape = self.model.inputs[0].shape
        self.nchw_layout = self.input_shape[1] == 3
        output_shape = self.model.outputs[0].shape
        if len(output_shape) not in (2, 4):
            raise RuntimeError("The model expects output shape [1, n, 1, 1] or [1, n], got {}".format(output_shape))

        self.faces_database = None
        self.match_threshold = match_threshold
        self.match_algo = match_algo

    def set_faces_database(self, database):
        self.faces_database = database

    def get_identity_label(self, id):
        if not self.faces_database or id == self.UNKNOWN_ID:
            return self.UNKNOWN_ID_LABEL
        return self.faces_database[id].label

    def preprocess(self, frame, rois, landmarks):
        image = frame.copy()
        inputs = cut_rois(image, rois)
        self._align_rois(inputs, landmarks)
        inputs = [resize_input(input, self.input_shape, self.nchw_layout) for input in inputs]
        return inputs

    def enqueue(self, input):
        return super(FaceIdentifier, self).enqueue({self.input_tensor_name: input})

    def start_async(self, frame, rois, landmarks):
        inputs = self.preprocess(frame, rois, landmarks)
        for input in inputs:
            self.enqueue(input)

    def get_threshold(self):
        return self.match_threshold

    def postprocess(self):
        descriptors = self.get_descriptors()

        matches = []
        if len(descriptors) != 0:
            matches = self.faces_database.match_faces(descriptors, self.match_algo)

        results = []
        unknowns_list = []
        for num, match in enumerate(matches):
            id = match[0]
            distance = match[1]
            if self.match_threshold < distance:
                id = self.UNKNOWN_ID
                unknowns_list.append(num)
            else:
                print()
                    

            results.append(self.Result(id, distance, descriptors[num]))
        return results, unknowns_list

    def get_descriptors(self):
        return [out.flatten() for out in self.get_outputs()]

    @staticmethod
    def normalize(array, axis):
        mean = array.mean(axis=axis)
        array -= mean
        std = array.std()
        array /= std
        return mean, std

    @staticmethod
    def get_transform(src, dst):
        assert np.array_equal(src.shape, dst.shape) and len(src.shape) == 2, \
            '2d input arrays are expected, got {}'.format(src.shape)
        src_col_mean, src_col_std = FaceIdentifier.normalize(src, axis=0)
        dst_col_mean, dst_col_std = FaceIdentifier.normalize(dst, axis=0)

        u, _, vt = np.linalg.svd(np.matmul(src.T, dst))
        r = np.matmul(u, vt).T

        transform = np.empty((2, 3))
        transform[:, 0:2] = r * (dst_col_std / src_col_std)
        transform[:, 2] = dst_col_mean.T - np.matmul(transform[:, 0:2], src_col_mean.T)
        return transform

    def _align_rois(self, face_images, face_landmarks):
        assert len(face_images) == len(face_landmarks), \
            'Input lengths differ, got {} and {}'.format(len(face_images), len(face_landmarks))

        for image, image_landmarks in zip(face_images, face_landmarks):
            scale = np.array((image.shape[1], image.shape[0]))
            desired_landmarks = np.array(self.REFERENCE_LANDMARKS, dtype=np.float64) * scale
            landmarks = image_landmarks * scale

            transform = FaceIdentifier.get_transform(desired_landmarks, landmarks)
            cv2.warpAffine(image, transform, tuple(scale), image, flags=cv2.WARP_INVERSE_MAP)
            









#Face detection



import sys
from argparse import ArgumentParser
from pathlib import Path
from time import perf_counter
import cv2
import numpy as np
from openvino.runtime import Core, get_version
from utils import crop
from landmarks_detector import LandmarksDetector
from face_detector import FaceDetector
from faces_database import FacesDatabase
import monitors
from helpers import resolution
from images_capture import open_images_capture
from openvino.model_zoo.model_api.models import OutputTransform
from openvino.model_zoo.model_api.performance_metrics import PerformanceMetrics




DEVICE_KINDS = ['CPU', 'GPU', 'MYRIAD', 'HETERO', 'HDDL']


def build_argparser():
    parser = ArgumentParser()

    general = parser.add_argument_group('General')
    general.add_argument('-i', '--input',
                         help='Required. An input to process. The input must be a single image, '
                              'a folder of images, video file or camera id.' ,default=0)
    general.add_argument('--loop', default=False, action='store_true',
                         help='Optional. Enable reading the input in a loop.')
    general.add_argument('-o', '--output',
                         help='Optional. Name of the output file(s) to save.',default=None)
    general.add_argument('-limit', '--output_limit', default=1000, type=int,
                         help='Optional. Number of frames to store in output. '
                              'If 0 is set, all frames are stored.',)
    general.add_argument('--output_resolution', default=None, type=resolution,
                         help='Optional. Specify the maximum output window resolution '
                              'in (width x height) format. Example: 1280x720. '
                              'Input frame size used by default.')
    general.add_argument('--no_show', action='store_true',default=False,
                         help="Optional. Don't show output.")
    general.add_argument('--crop_size', default=(0, 0), type=int, nargs=2,
                         help='Optional. Crop the input stream to this resolution.')
    general.add_argument('--match_algo', default='HUNGARIAN', choices=('HUNGARIAN', 'MIN_DIST'),
                         help='Optional. Algorithm for face matching. Default: HUNGARIAN.')
    general.add_argument('-u', '--utilization_monitors', default='', type=str,
                         help='Optional. List of monitors to show initially.')

    gallery = parser.add_argument_group('Faces database')
    gallery.add_argument('-fg', default=eml, help='Optional. Path to the face images directory.')
    gallery.add_argument('--run_detector', action='store_true',
                         help='Optional. Use Face Detection model to find faces '
                              'on the face images, otherwise use full images.',default=False)
    gallery.add_argument('--allow_grow', action='store_true',
                         help='Optional. Allow to grow faces gallery and to dump on disk. '
                              'Available only if --no_show option is off.',default=False)

    models = parser.add_argument_group('Models')
    models.add_argument('-m_fd', type=Path, 
                        help='Required. Path to an .xml file with Face Detection model.',default='models/face-detection-retail-0004/FP16/face-detection-retail-0004.xml')
    models.add_argument('-m_lm', type=Path, 
                        help='Required. Path to an .xml file with Facial Landmarks Detection model.',default='models/landmarks-regression-retail-0009/FP16/landmarks-regression-retail-0009.xml')
    models.add_argument('-m_reid', type=Path, 
                        help='Required. Path to an .xml file with Face Reidentification model.',default='models/face-reidentification-retail-0095/FP16/face-reidentification-retail-0095.xml')
    models.add_argument('--fd_input_size', default=(0, 0), type=int, nargs=2,
                        help='Optional. Specify the input size of detection model for '
                             'reshaping. Example: 500 700.')

    infer = parser.add_argument_group('Inference options')
    infer.add_argument('-d_fd', default='CPU', choices=DEVICE_KINDS,
                       help='Optional. Target device for Face Detection model. '
                            'Default value is CPU.')
    infer.add_argument('-d_lm', default='CPU', choices=DEVICE_KINDS,
                       help='Optional. Target device for Facial Landmarks Detection '
                            'model. Default value is CPU.')
    infer.add_argument('-d_reid', default='CPU', choices=DEVICE_KINDS,
                       help='Optional. Target device for Face Reidentification '
                            'model. Default value is CPU.')
    infer.add_argument('-v', '--verbose', action='store_true',
                       help='Optional. Be more verbose.',default=True)
    infer.add_argument('-t_fd', metavar='[0..1]', type=float, default=0.6,
                       help='Optional. Probability threshold for face detections.')
    infer.add_argument('-t_id', metavar='[0..1]', type=float, default=0.3,
                       help='Optional. Cosine distance threshold between two vectors '
                            'for face identification.')
    infer.add_argument('-exp_r_fd', metavar='NUMBER', type=float, default=1.15,
                       help='Optional. Scaling ratio for bboxes passed to face recognition.')
    return parser


class FrameProcessor:
    QUEUE_SIZE = 16

    def __init__(self, args):
        self.allow_grow = args.allow_grow and not args.no_show

        log.info('OpenVINO Runtime')
        log.info('\tbuild: {}'.format(get_version()))
        core = Core()

        self.face_detector = FaceDetector(core, args.m_fd,
                                          args.fd_input_size,
                                          confidence_threshold=args.t_fd,
                                          roi_scale_factor=args.exp_r_fd)
        self.landmarks_detector = LandmarksDetector(core, args.m_lm)
        self.face_identifier = FaceIdentifier(core, args.m_reid,
                                              match_threshold=args.t_id,
                                              match_algo=args.match_algo)

        self.face_detector.deploy(args.d_fd)
        self.landmarks_detector.deploy(args.d_lm, self.QUEUE_SIZE)
        self.face_identifier.deploy(args.d_reid, self.QUEUE_SIZE)

        log.debug('Building faces database using images from {}'.format(args.fg))
        self.faces_database = FacesDatabase(args.fg, self.face_identifier,
                                            self.landmarks_detector,
                                            self.face_detector if args.run_detector else None, args.no_show)
        self.face_identifier.set_faces_database(self.faces_database)
        log.info('Database is built, registered {} identities'.format(len(self.faces_database)))

    def process(self, frame):
        orig_image = frame.copy()

        rois = self.face_detector.infer((frame,))
        if self.QUEUE_SIZE < len(rois):
            log.warning('Too many faces for processing. Will be processed only {} of {}'
                        .format(self.QUEUE_SIZE, len(rois)))
            rois = rois[:self.QUEUE_SIZE]

        landmarks = self.landmarks_detector.infer((frame, rois))
        face_identities, unknowns = self.face_identifier.infer((frame, rois, landmarks))
        if self.allow_grow and len(unknowns) > 0:
            for i in unknowns:
                # This check is preventing asking to save half-images in the boundary of images
                if rois[i].position[0] == 0.0 or rois[i].position[1] == 0.0 or \
                    (rois[i].position[0] + rois[i].size[0] > orig_image.shape[1]) or \
                    (rois[i].position[1] + rois[i].size[1] > orig_image.shape[0]):
                    continue
                crop_image = crop(orig_image, rois[i])
                name = self.faces_database.ask_to_save(crop_image)
                if name:
                    id = self.faces_database.dump_faces(crop_image, face_identities[i].descriptor, name)
                    face_identities[i].id = id

        return [rois, landmarks, face_identities]


def draw_detections(frame, frame_processor, detections, output_transform):
    size = frame.shape[:2]
    frame = output_transform.resize(frame)
    for roi, landmarks, identity in zip(*detections):
        text = frame_processor.face_identifier.get_identity_label(identity.id)
        if identity.id != FaceIdentifier.UNKNOWN_ID:
            global time_function_done
            if (time_function_done + 2) < time.time():
                time_function_done = time.time()
                Thread(target=uploadCapture, args=(frame,text+' is at Home!!' )).start()
            text += ' %.2f%%' % (100.0 * (1 - identity.distance))

        xmin = max(int(roi.position[0]), 0)
        ymin = max(int(roi.position[1]), 0)
        xmax = min(int(roi.position[0] + roi.size[0]), size[1])
        ymax = min(int(roi.position[1] + roi.size[1]), size[0])
        xmin, ymin, xmax, ymax = output_transform.scale([xmin, ymin, xmax, ymax])
        cv2.rectangle(frame, (xmin, ymin), (xmax, ymax), (0, 220, 0), 2)

        for point in landmarks:
            x = xmin + output_transform.scale(roi.size[0] * point[0])
            y = ymin + output_transform.scale(roi.size[1] * point[1])
            cv2.circle(frame, (int(x), int(y)), 1, (0, 255, 255), 2)
        textsize = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, 0.7, 1)[0]
        cv2.rectangle(frame, (xmin, ymin), (xmin + textsize[0], ymin - textsize[1]), (255, 255, 255), cv2.FILLED)
        cv2.putText(frame, text, (xmin, ymin), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 1)

    return frame

def center_crop(frame, crop_size):
    fh, fw, _ = frame.shape
    crop_size[0], crop_size[1] = min(fw, crop_size[0]), min(fh, crop_size[1])
    return frame[(fh - crop_size[1]) // 2 : (fh + crop_size[1]) // 2,
                 (fw - crop_size[0]) // 2 : (fw + crop_size[0]) // 2,
                 :]

def fmain():
    
    args = build_argparser().parse_args()
    
    cap = open_images_capture(args.input, args.loop)
    frame_processor = FrameProcessor(args)

    frame_num = 0
    metrics = PerformanceMetrics()
    presenter = None
    output_transform = None
    input_crop = None
    if args.crop_size[0] > 0 and args.crop_size[1] > 0:
        input_crop = np.array(args.crop_size)
    elif not (args.crop_size[0] == 0 and args.crop_size[1] == 0):
        raise ValueError('Both crop height and width should be positive')
    video_writer = cv2.VideoWriter()

    while True:
        start_time = perf_counter()
        frame = cap.read()
        if frame is None:
            if frame_num == 0:
                raise ValueError("Can't read an image from the input")
            break
        if input_crop:
            frame = center_crop(frame, input_crop)
        if frame_num == 0:
            output_transform = OutputTransform(frame.shape[:2], args.output_resolution)
            if args.output_resolution:
                output_resolution = output_transform.new_resolution
            else:
                output_resolution = (frame.shape[1], frame.shape[0])
            presenter = monitors.Presenter(args.utilization_monitors, 55,
                                           (round(output_resolution[0] / 4), round(output_resolution[1] / 8)))
            if args.output and not video_writer.open(args.output, cv2.VideoWriter_fourcc(*'MJPG'),
                                                     cap.fps(), output_resolution):
                raise RuntimeError("Can't open video writer")

        detections = frame_processor.process(frame)
        presenter.drawGraphs(frame)
        frame = draw_detections(frame, frame_processor, detections, output_transform)
        metrics.update(start_time, frame)

        frame_num += 1
        if video_writer.isOpened() and (args.output_limit <= 0 or frame_num <= args.output_limit):
            video_writer.write(frame)
        global sel
        if not args.no_show:
            cv2.imshow('Face recognition ', frame)
            key = cv2.waitKey(1)
            # Quit
            if key in {ord('q'), ord('Q'), 27}:
                print('yeh tha')
                break
            presenter.handleKey(key)
            

    metrics.log_total()
    for rep in presenter.reportMeans():
        log.info(rep)






#multiprocess and streams


def runMode():
        global areas,temp,IntPoints
        d= ast.literal_eval(IntPoints)
        values = d.values()
        values_list = list(values)
                  
        keys_list = list(d)
        global intMode
        if len(values_list)<=2:
           
            print(len(values_list))
            
            intMode=0
            global boundaryLines
            boundaryLines= [
                boundaryLine([ int(780-(values_list[0]-1)),  int(keys_list[0]),  int(780-(values_list[1]-1)), int(keys_list[1] )])
                    ]  

            
        else:
            intMode=1   
        d = {}
        new_list = [780-(x-1) for x in values_list]
        for key in new_list:
            for value in keys_list:
                d[key] = value
                keys_list.remove(value)
                break              
        ar= list(map(list, d.items()))            
        areas=[area(ar)] 
            
        
         
        if mode==1:
            time.sleep(3)
            print('int chalaya')
            cv2.startWindowThread()
            global t1
            t1 = thread_with_exception('Thread 1')
            t1.start()
            
            
    
            
            
        elif mode==2 and temp==IntPoints:
            time.sleep(3)
            print('face chalaya')
            cv2.startWindowThread()
            global t2
            t2 = thread_with_exception('Thread 2')
            t2.start()
            
            #p2= multiprocessing.Process(target = fmain)
            #p2.start()
            
            # others =' -m_fd C:/models/face-detection-retail-0004/FP16/face-detection-retail-0004.xml -m_lm C:/models/landmarks-regression-retail-0009/FP16/landmarks-regression-retail-0009.xml -m_reid C:/models/face-reidentification-retail-0095/FP16/face-reidentification-retail-0095.xml --verbose  -fg "C:/face_gallery" '                     
            #v=str(pathlib.Path().resolve())
            #s='\\face_recognition_demo\\python\\face_recognition_demo.py '
            #ck='"'+v+s+'"' 
            #pth = r'{}'.format(ck)
            #print(pth)
            #os.system('"python ' + pth +'"' )

def updatedata():
        
        global deviceToken,IntPoints,auth,mode,db,sel,el,tr,areas,rtsp,cap
        dbs=db
        doc_ref = dbs.collection(u'DB').document(auth.current_user['localId'])
        doc = doc_ref.get()
        deviceToken=doc.to_dict()["deviceToken"]
        IntPoints=doc.to_dict()["Intrusion Points"]
        rtsp=doc.to_dict()["RTSP"]
        mode=doc.to_dict()["Mode"]
        global temp
        if mode==1 and temp==IntPoints:
                try: 
                    cv2.destroyAllWindows()
                    t2.raise_exception()
                    t2.join()
                    temp=IntPoints
                    
                    
                     
                except:
                    print("face hatam krne ki koshish") 

        elif mode==1 and temp!=IntPoints:
                try:  
                    
                    cv2.destroyAllWindows()
                    t1.raise_exception()
                    t1.join()
                    temp=IntPoints
                    
                    cv2.destroyAllWindows()

                   
                    
                    
                    
                    
                    
                     
                   
                except:
                    print("intrusion hatam krne ki koshish explicit")     
        







                try: 
                    cv2.destroyAllWindows()
            
                    t2.raise_exception()
                    t2.join()
                    temp=IntPoints
                   
                     
                except:
                    print("face hatam krne ki koshish")                 

        else:


            

                try:  
                    cv2.destroyAllWindows()
                    t1.raise_exception()
                    t1.join()
                    temp=IntPoints
                    
                    cv2.destroyAllWindows()
                    
                    
                    
                     
                   
                except:
                    print("intrusion hatam krne ki koshish")   

                try: 
                    cv2.destroyAllWindows()
                    t2.raise_exception()
                    t2.join()
                    temp=IntPoints
                  
                    
                     
                except:
                    print("face hatam krne ki koshish") 

  
        
        
    
        



def on_snapshot(doc_snapshot, changes, read_time):
            
         for doc in doc_snapshot:
                 
                 updatedata()
                 runMode()
                 
   

def listener(doc_ref):
        
        doc_watch = doc_ref.on_snapshot(on_snapshot)


















ctypes.windll.shcore.SetProcessDpiAwareness(True)





class LoginPage:
    def __init__(self):
        self.window = Tk()
        self.window.geometry("1000x600")
        self.window.configure(bg = "#ffffff")
        self.window.resizable(False,False)
        self.email=''
        self.password=''


        self.window.title('Login Page')





        canvas = Canvas(
        self.window,
        bg = "#ffffff",
        height = 1920,
        width = 1080,
        bd = 0,
        highlightthickness = 0,
        relief = "ridge")
        canvas.place(x = 0, y = -200)

        background_img = PhotoImage(file = f"background.png")
        background = canvas.create_image(
        500, 500,
        image=background_img)

        entry0_img = PhotoImage(file = f"img_textBox0.png")
        entry0_bg = canvas.create_image(
        675.0, 458,
        image = entry0_img)

        self.entry0 = Entry(
        bd = 0,
        bg = "#f6f6f6",
        highlightthickness = 0)

        self.entry0.place(
        x = 598.0, y = 291,
        width = 160.0,
        height = 28)

        entry1_img = PhotoImage(file = f"img_textBox1.png")
        entry1_bg = canvas.create_image(
        675.0, 505,
        image = entry1_img)

        self.entry1 = Entry(
        bd = 0,
        bg = "#f6f6f6",
        highlightthickness = 0)

        self.entry1.place(
        x = 598.0, y = 244,
        width = 160.0,
        height = 28)

        img0 = PhotoImage(file = f"img0.png")
        b0 = Button(
        image = img0,
        borderwidth = 0,
        highlightthickness = 0,
        command = self.btn_clicked,
        relief = "flat")

        b0.place(
        x = 575.0, y = 345,
        width = 96,
        height = 34)

        img1 = PhotoImage(file = f"img1.png")
        b1 = Button(
        image = img1,
        borderwidth = 0,
        highlightthickness = 0,
        command = self.btn_clicked2,
        relief = "flat")

        b1.place(
        x = 685, y = 345,
        width = 94,
        height = 30)
        self.window.mainloop()


    def btn_clicked2(self):
               webbrowser.open('http://google.com')


    def btn_clicked(self):
               global eml
               eml=self.entry1.get()
               pwd=self.entry0.get()
               
               
               
               try:
                        global deviceToken,IntPoints,auth
                        
                        auth.sign_in_with_email_and_password(eml,pwd)
                        try:
                            shutil.rmtree(eml)
                        except:
                            print('NEW USER')                                
                        os.mkdir(eml)
                        storage = firebase.storage()
                        datadir = eml

                        all_files = storage.child(eml).list_files()

                        for file in all_files:
                            try:
                                file.download_to_filename(file.name)
                            except:
                                print('Download Processing')

                       





                                





                        global temp
                        updatedata()
                        temp=IntPoints
                        self.email=eml
                        self.password=pwd
                        doc_ref = db.collection(u'DB').document(auth.current_user['localId'])
                        listener(doc_ref)
                        
                        
                       
                        
                       
                        
               except Exception as e:
                    print(e)
                    tkMessageBox.showinfo( "Invalid Username or Password","Invalid Username or Password")


              




def page():
    
       
       LoginPage()
       
    
    


if __name__ == '__main__':
        
        page()

