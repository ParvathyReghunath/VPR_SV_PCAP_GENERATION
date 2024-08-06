import customtkinter
from PIL import ImageTk, Image
import pcap_gen_v2
import tkinter
from tkinter import messagebox
import matplotlib.pyplot as plt 
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import FreeSimpleGUI as sg

customtkinter.set_appearance_mode("Dark")  # Modes: system (default), light, dark
customtkinter.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

app = customtkinter.CTk()  # create CTk window like you do with the Tk window
app.title("MevantUI")
ws = app.winfo_screenwidth()               
hs = app.winfo_screenheight()
x = -8
y = 0
app.geometry('%dx%d+%d+%d' % (ws-2, hs-78, x, y))
#app.state("zoomed")
#customtkinter.deactivate_automatic_dpi_awareness()
#customtkinter.set_widget_scaling(1.27)  # widget dimensions and text size
#customtkinter.set_window_scaling(1.0)  # window geometry dimensions
#1536 864

def get_scaling():
    # called before window created
    root = sg.tk.Tk()
    scaling = root.winfo_fpixels('1i')/72
    root.destroy()
    return scaling

# Find the number in original screen when GUI designed.
my_scaling = 1.334646962233169      # call get_scaling()
my_width, my_height = 1536, 864     # call sg.Window.get_screen_size()

# Get the number for new screen
scaling_old = get_scaling()
width, height = sg.Window.get_screen_size()

scaling = scaling_old * min(width / my_width, height / my_height)

sg.set_options(scaling=scaling)

count=0
def theme_switch():
    global count
    if (count%2)!=0:
        customtkinter.set_appearance_mode("Dark")
        global pic_label2
        pic_label2.place_forget()
        count+=1
    else:
        customtkinter.set_appearance_mode("Light")
        # Create an object of tkinter ImageTk
        img = customtkinter.CTkImage(Image.open("Kalki.png"),size=(170, 45))

        # Create a Label Widget to display the text or Image
        pic_label2 = customtkinter.CTkLabel(app,text="", image = img)
        pic_label2.place(x=1320,y=25)
        count+=1

switch=customtkinter.CTkSwitch(app,text="Switch Theme",command=theme_switch)
switch.place(x=50,y=hs-109)

switch=customtkinter.CTkLabel(app,text="Version 1.0.0.2")
switch.place(x=ws-136,y=hs-109)

tabview = customtkinter.CTkTabview(master=app,width=ws-20,height=hs)
tabview.pack(pady=(80,40))

tab1=tabview.add("DATA")  # add tab at the end
tab2=tabview.add("GRAPH")  # add tab at the end
tab3=tabview.add("GENERATE")
tabview.set("DATA")  # set currently visible tab

state_name=[]
# creating all labels
my_label = customtkinter.CTkLabel(tab1, text='STREAM', font=("Arial", 15))
my_label.place(x=8, y=40)
my_label = customtkinter.CTkLabel(tab1, text='STATE-1', font=("Arial", 15))
my_label.place(x=285, y=40)
my_label = customtkinter.CTkLabel(tab1, text='STATE-2', font=("Arial", 15))
my_label.place(x=705, y=40)
my_label = customtkinter.CTkLabel(tab1, text='STATE-3', font=("Arial", 15))
my_label.place(x=1135, y=40)
my_label = customtkinter.CTkEntry(tab1, font=("Arial", 11),width=85)
my_label.insert(0,'DOBLMU0101')
my_label.place(x=0, y=100)
state_name.append(my_label)
my_label = customtkinter.CTkEntry(tab1, font=("Arial", 11),width=85)
my_label.insert(0,'DOBLMU0201')
my_label.place(x=0, y=170)
state_name.append(my_label)
my_label = customtkinter.CTkEntry(tab1, font=("Arial", 11),width=85)
state_name.append(my_label)
my_label.insert(0,'DOBLMU0301')
my_label.place(x=0, y=240)
my_label = customtkinter.CTkLabel(tab1, text='V', font=("Arial", 12))
my_label.place(x=90, y=87)
my_label = customtkinter.CTkLabel(tab1, text='I', font=("Arial", 12))
my_label.place(x=92, y=113)
my_label = customtkinter.CTkLabel(tab1, text='V', font=("Arial", 12))
my_label.place(x=90, y=157)
my_label = customtkinter.CTkLabel(tab1, text='I', font=("Arial", 12))
my_label.place(x=92, y=183)
my_label = customtkinter.CTkLabel(tab1, text='V', font=("Arial", 12))
my_label.place(x=90, y=227)
my_label = customtkinter.CTkLabel(tab1, text='I', font=("Arial", 12))
my_label.place(x=92, y=253)
a = 150
for y in range(3):
    my_label = customtkinter.CTkLabel(tab1, text='A', font=("Arial", 8))
    my_label.place(x=a, y=70)
    my_label = customtkinter.CTkLabel(tab1, text='B', font=("Arial", 8))
    my_label.place(x=a+105, y=70)
    my_label = customtkinter.CTkLabel(tab1, text='C', font=("Arial", 8))
    my_label.place(x=a+210, y=70)
    my_label = customtkinter.CTkLabel(tab1, text='N', font=("Arial", 8))
    my_label.place(x=a+310, y=70)
    a += 430
my_label = customtkinter.CTkLabel(tab1, text='REPETITION', font=("Arial", 11))
my_label.place(x=9, y=300)
my_label = customtkinter.CTkLabel(tab1, text='FREQUENCY', font=("Arial", 11))
my_label.place(x=8, y=400)
my_label = customtkinter.CTkLabel(tab1, text='DURATION', font=("Arial", 11))
my_label.place(x=11, y=350)

#creating entry boxes
#table entries
n=3
c=0
entries = []
final={}
for p in range(n):                                                               
        a=0
        b=48
        for q in range(105, 1000, 430):
                for j in range(8):
                        k=90+c
                        for i in range(2):
                                entry = customtkinter.CTkEntry(tab1,font=("Arial", 11), width=50, height=25)
                                entry.insert(0,"1")
                                entry.place(x=q, y=k)
                                entries.append(entry)
                                k+=25
                        q+=50
                        if j%2!=0:
                              q+=3
        c=c+70

#repetition box
entry = customtkinter.CTkEntry(tab1,font=("Arial", 10), width=60, height=25)
entry.insert(0,"0")
entry.place(x=715, y=300)
entries.append(entry)

#duration box
w = 285
for t in range(3):
    entry = customtkinter.CTkEntry(tab1,font=("Arial", 10), width=60, height=25)
    entry.insert(0,"%d"%(t+1))
    entry.place(x=w, y=350)
    entries.append(entry)
    w += 430

#frequency box
entry = customtkinter.CTkEntry(tab1,font=("Arial", 10), width=60, height=25)
entry.insert(0,"60")
entry.place(x=715, y=400)
entries.append(entry)

#vlan id on check
ent=customtkinter.CTkEntry(tab1,height=20,width=40,font=("Arial", 11))
ent1=customtkinter.CTkEntry(tab1,height=20,width=40,font=("Arial", 11))
ent2=customtkinter.CTkEntry(tab1,height=20,width=40,font=("Arial", 11))
entry_data=[]
c1=0
c2=0
c3=0
def toggle1():
    global ent
    global c1
    if c1==0:                               
        ent.place(x=1450,y=115)
        entry_data.append(ent)
        c1=1
    else:
        ent.place_forget()
        c1=0

def toggle2():
    global ent1
    global c2
    if c2==0:
        ent1.place(x=1450,y=185)
        entry_data.append(ent1)
        c2=1
    else:
        ent1.place_forget()
        c2=0

def toggle3():
    global ent2
    global c3
    if c3==0:
        ent2.place(x=1450,y=255)
        entry_data.append(ent2)
        c3=1
    else:
        ent2.place_forget()
        c3=0

#check boxes
check=[]
CheckVar1=customtkinter.StringVar()
C1 = customtkinter.CTkCheckBox(tab1, text = "Simulation",font=("Arial", 12), variable = CheckVar1, onvalue = 1, offvalue = 0,checkbox_height=20,checkbox_width=20,border_width=1,width=0)
C1.place(x=1390,y=90)
check.append(CheckVar1)
CheckVar2=customtkinter.StringVar()
C1 = customtkinter.CTkCheckBox(tab1, text = "VLAN",font=("Arial", 12), variable = CheckVar2, onvalue = 1, offvalue = 0,command=toggle1,checkbox_height=20,checkbox_width=20,border_width=1,width=0)
C1.place(x=1390,y=115)
check.append(CheckVar2)
CheckVar3=customtkinter.StringVar()
C1 = customtkinter.CTkCheckBox(tab1, text = "Simulation",font=("Arial", 12), variable = CheckVar3, onvalue = 1, offvalue = 0,checkbox_height=20,checkbox_width=20,border_width=1,width=0)
C1.place(x=1390,y=160)
check.append(CheckVar3)
CheckVar4=customtkinter.StringVar()
C1 = customtkinter.CTkCheckBox(tab1, text = "VLAN",font=("Arial", 12), variable = CheckVar4, onvalue = 1, offvalue = 0,command=toggle2,checkbox_height=20,checkbox_width=20,border_width=1,width=0)
C1.place(x=1390,y=185)
check.append(CheckVar4)
CheckVar5=customtkinter.StringVar()
C1 = customtkinter.CTkCheckBox(tab1, text = "Simulation",font=("Arial", 12), variable = CheckVar5, onvalue = 1, offvalue = 0,checkbox_height=20,checkbox_width=20,border_width=1,width=0)
C1.place(x=1390,y=230)
check.append(CheckVar5)
CheckVar6=customtkinter.StringVar()
C1 = customtkinter.CTkCheckBox(tab1, text = "VLAN",font=("Arial", 12), variable = CheckVar6, onvalue = 1, offvalue = 0,command=toggle3,checkbox_height=20,checkbox_width=20,border_width=1,width=0)
C1.place(x=1390,y=255)
check.append(CheckVar6)

# Create an object of tkinter ImageTk
img = customtkinter.CTkImage(Image.open("Kalki_light.png"),size=(210, 60))

# Create a Label Widget to display the text or Image
label = customtkinter.CTkLabel(app,text="", image = img)
label.place(x=1300,y=20)

#File path and file name label
my_lab=customtkinter.CTkLabel(tab3,text="File Path: ",font=("Arial", 13))
my_lab.place(x=600,y=200)
my_lab=customtkinter.CTkLabel(tab3,text="File Name: ",font=("Arial", 13))
my_lab.place(x=600,y=250)

#entry box file path
entry=customtkinter.CTkEntry(tab3,font=("Arial", 11),width=250,height=30)
entry.insert(0,"C:\\Users\\Eldhose Joseph\\Desktop\\Project\\")
entry.place(x=700, y=200)
entries.append(entry)

#entry box file name
entry=customtkinter.CTkEntry(tab3,font=("Arial", 11),width=250,height=30)
entry.insert(0,"output")
entry.place(x=700, y=250)
entries.append(entry)

#storage function
def add_to_list():
    global entries
    global final
    l=[]
    D1={}
    D2={}
    D3={}
    for j in entries:
         l.append(j.get())
    l1=l[0:48]
    l2=l[48:96]
    l3=l[96:144]
    l4=l[145:148]

    data=[]
    for k in state_name:
          data.append(k.get())
    
    data2=[]
    for k in check:
        if (k.get()=='1' or k.get()=='0'):
            data2.append(k.get())
        else:
             data2.append('0')

    data3=[]
    for k in entry_data:
        data3.append(k.get())
    while(len(data3)<3):
        data3.append('') 

    D1["state1"]=l1[0:16]
    D1["state2"]=l1[16:32]
    D1["state3"]=l1[32:48]
    D1["svid"]=data[0]
    D1["VLANID"]=data3[0]
    D1["simulated"]=data2[0]
    D1["tagged"]=data2[1]

    D2["state1"]=l2[0:16]
    D2["state2"]=l2[16:32]
    D2["state3"]=l2[32:48]
    D2["svid"]=data[1]
    D2["VLANID"]=data3[1]
    D2["simulated"]=data2[2]
    D2["tagged"]=data2[3]
        
    D3["state1"]=l3[0:16]
    D3["state2"]=l3[16:32]
    D3["state3"]=l3[32:48]
    D3["svid"]=data[2]
    D3["VLANID"]=data3[2]
    D3["simulated"]=data2[4]
    D3["tagged"]=data2[5]

    final["repetition"]=l[144]
    final["duration"]=l4         
    final["states"]=[D1,D2,D3]
    final["frequency"]=l[148]
    final["filepath"]=l[149]
    final["filename"]=l[150]
    result=pcap_gen_v2.states(final)
    if(result):
        #my_lab2=customtkinter.CTkLabel(tab3,text="FILE GENERATED",text_color="green")
        #my_lab2.place(x=730,y=350)
        messagebox.showinfo("STATUS","FILE SUCCESSFULLY GENERATED")
    else:
        #my_lab2=customtkinter.CTkLabel(tab3,text="ERROR OCCURED",text_color="red")
        #my_lab2.place(x=730,y=350)
        messagebox.showerror("ERROR OCCURED","Please check pcap_gen_v2.py again")

#generate button
my_button=customtkinter.CTkButton(tab3,text="GENERATE",font=("Arial", 14),command=add_to_list,width=120,height=30)
my_button.place(x=720,y=300)

#dict structure
'''
final={
'repetition': '0', 
'duration': ['1', '2', '3'], 
'states': [
            {'state1': ['2', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'], 'state2': ['1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'], 'state3': ['1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'], 'SVID': 'KALKIMU001', 'VLANID': '10101', 'Simulated': 1, 'tagged': 1}, 
            {'state1': ['1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'], 'state2': ['2', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'], 'state3': ['1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'], 'SVID': 'KALKIMU002', 'VLANID': '', 'Simulated': 0, 'tagged': 1}, 
            {'state1': ['1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'], 'state2': ['1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'], 'state3': ['2', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'], 'SVID': 'KALKIMU003', 'VLANID': '', 'Simulated': 0, 'tagged': 0}
          ], 
'frequency': '60', 
'filepath': 'C:\\Users\\Eldhose Joseph\\Desktop\\Project\\', 
'filename': 'output'
}'''

def create_graph():
    global call
    global canvas
    global final
    global toolbar
    global entries
    l=[]
    D1={}
    D2={}
    D3={}
    for j in entries:
        l.append(j.get())
    l1=l[0:48]
    l2=l[48:96]
    l3=l[96:144]
    l4=l[145:148]

    data=[]
    for k in state_name:
        data.append(k.get())
    
    data2=[]
    for k in check:
        data2.append(k.get())
    
    data3=[]
    for k in entry_data:
        data3.append(k.get())
    
    D1["state1"]=l1[0:16]
    D1["state2"]=l1[16:32]
    D1["state3"]=l1[32:48]
    D1["SVID"]=data[0]
    #D1["VLANID"]=data3[0]
    D1["Simulated"]=data2[0]
    D1["tagged"]=data2[1]

    D2["state1"]=l2[0:16]
    D2["state2"]=l2[16:32]
    D2["state3"]=l2[32:48]
    D2["SVID"]=data[1]
    #D2["VLANID"]=data3[1]
    D2["Simulated"]=data2[2]
    D2["tagged"]=data2[3]
        
    D3["state1"]=l3[0:16]
    D3["state2"]=l3[16:32]
    D3["state3"]=l3[32:48]
    D3["SVID"]=data[2]
    #D3["VLANID"]=data3[2]
    D3["Simulated"]=data2[4]
    D3["tagged"]=data2[5]

    final["repetition"]=l[144]
    final["duration"]=l4         
    final["states"]=[D1,D2,D3]
    final["frequency"]=l[148]

    #print(final)
    if call!=1:
        canvas.get_tk_widget().pack_forget()
    
    fig, axs = plt.subplots(nrows=8, figsize=(16, 6.3))
    
    canvas = FigureCanvasTkAgg(fig, master=tab2)
    canvas.get_tk_widget().pack()                                   
    # Create a figure with eight subplots arranged vertically

    c=1
    d=0
    # Generate and display the graphs
    for i, ax in enumerate(axs):
        t = np.arange(0, float(final["duration"][0]), 0.000028)
        y = float(final["states"][int(selection)]["state1"][d]) * np.sin(2 * np.pi * int(final["frequency"]) * t + int(final["states"][int(selection)]["state1"][d+2]))

        t1 = np.arange(float(final["duration"][0]), float(final["duration"][1]), 0.000028)
        y1 = float(final["states"][int(selection)]["state2"][d]) * np.sin(2 * np.pi * int(final["frequency"]) * t1 + int(final["states"][int(selection)]["state2"][d+2]))

        t2 = np.arange(float(final["duration"][1]), float(final["duration"][2]), 0.000028)
        y2 = float(final["states"][int(selection)]["state3"][d]) * np.sin(2 * np.pi * int(final["frequency"]) * t2 + int(final["states"][int(selection)]["state3"][d+2]))
        
        ax.plot(t, y, color="blue", label="STATE-1")
        ax.plot(t1, y1, color="red", label="STATE-2")
        ax.plot(t2, y2, color="green", label="STATE-3")
        
        ax.set_xlim(0, float(final["duration"][2]))

        if i % 2 == 0:
            ax.set_ylabel('<')
        else:
            ax.set_ylabel('--')

        if c==1:
            ax.legend(loc='upper right', bbox_to_anchor=(1.1, 1))
        #ax.legend()
        if(c%2==0):    
                d=d+2
        else:
            d=d+1
        c=c+1

        if i < len(axs) - 1:
            ax.set_xticks([])
            ax.set_xlim(0, float(final["duration"][2]))
        else:
            ax.set_xlim(0, float(final["duration"][2]))
            ax.set_xlabel('time')
    
    plt.subplots_adjust(hspace=0.2,top=0.95, bottom=0.08, left=0.05)

    if call==0:
        toolbar.pack_forget()
        
    toolbar = NavigationToolbar2Tk(canvas, tab2)
    fig.canvas.toolbar.pack(side=tkinter.BOTTOM, fill=tkinter.X)
    toolbar.update()
    call=0

def callback(choice):
    global selection
    if choice=="DOBLMU0101":
        selection=0
    elif choice=="DOBLMU0201":
        selection=1
    elif choice=="DOBLMU0301":
        selection=2

call=1
selection=0
combobox = customtkinter.CTkComboBox(master=tab2,
                                     values=["DOBLMU0101","DOBLMU0201","DOBLMU0301"],
                                     command=callback)
combobox.place(x=600,y=10)
combobox.set("DOBLMU0101") 

but=customtkinter.CTkButton(tab2,text="DRAW",command=create_graph)
but.place(x=800,y=10)

lab=customtkinter.CTkLabel(tab2,text="")
lab.pack()

lab=customtkinter.CTkLabel(tab2,text="")
lab.pack()

img = customtkinter.CTkImage(Image.open("MEVANT.png"),size=(150, 50))
pic_label2 = customtkinter.CTkLabel(app,text="", image = img)
pic_label2.place(x=60,y=25)

app.mainloop()