import os
from tkinter.filedialog import askopenfilename
from tkinter import *

content = ''
file_path = ''

def open_file():
    global content
    global file_path

    filename = askopenfilename(initialdir=os.getcwd(),initialfile="sam_test")
    infile = open(filename, 'r')
    content = infile.read()
    file_path = os.path.dirname(filename)
    entry.delete(0, END)
    entry.insert(0, filename)
    return content

def process_file(content):
    print(content)

#~~~~~~ GUI ~~~~~~~~
root = Tk()
root.title('SAM File Crack')
root.geometry("698x120+250+100")

mf = Frame(root)
mf.pack()

f1 = Frame(mf, width=700, height=250)
f1.pack(fill=X)
f2 = Frame(mf, width=700, height=250)
f2.pack()

file_path = StringVar

Label(f1,text='Select a valid Windows SAM  file \n (Try sam_test in the current working directory)').grid(row=0, column=0, sticky='e')
entry = Entry(f1, width=50, textvariable=file_path)
entry.grid(row=0,column=1,padx=2,pady=2,sticky='we',columnspan=25)
Button(f1, text="Browse", command=open_file).grid(row=0, column=27, sticky='ew', padx=8, pady=4)
Button(f2, text="Crack Accounts", width=32, command=lambda: process_file(content)).grid(sticky='ew', padx=10, pady=10)

root.mainloop()
#~~~~~~~~~~~~~~~~~~~