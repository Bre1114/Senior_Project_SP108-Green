#Run application from here
import tkinter as tk
from main_window import create_window

#Creates main window
window = tk.Tk()
window.title('ASM Dashboard')
window.geometry('1250x780')
window.minsize(950, 600)
create_window(window)
window.mainloop()
