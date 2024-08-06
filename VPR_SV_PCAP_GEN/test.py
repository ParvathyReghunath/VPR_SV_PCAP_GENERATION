import tkinter  as tk 
from tkinter import *
from tkinter import ttk
my_w = tk.Tk()
my_w.geometry("400x200")  
my_tabs = ttk.Notebook(my_w,padding=10) # declaring 

tab0 = ttk.Frame(my_tabs)
tab1 = ttk.Frame(my_tabs)
tab2 = ttk.Frame(my_tabs)

my_tabs.add(tab0, text ='Tab-0') # adding tab
my_tabs.add(tab1, text ='Tab-1') # adding tab 
my_tabs.add(tab2, text ='Tab-2') # adding tab 
my_tabs.pack(expand = 1, fill ="both")

font1=('time',22,'normal')
l1=tk.Label(tab0,text='I am tab-0',bg='yellow',font=font1)
l1.place(relx=0.4,rely=0.2) # using place
l2=tk.Label(tab1,text='I am tab-1',bg='yellow',font=font1)
l2.place(relx=0.4,rely=0.2) # using grid 
l3=tk.Label(tab2,text='I am tab-2',bg='yellow',font=font1)
l3.place(relx=0.4,rely=0.2) # using place

def my_msg(*args):
    t_nos=str(my_tabs.index(my_tabs.select()))
    l4.config(text='tab No: '+ t_nos)
	
my_tabs.bind('<<NotebookTabChanged>>',my_msg)

l4=tk.Label(my_w,text='message here')
l4.pack(side=LEFT)

my_w.mainloop()