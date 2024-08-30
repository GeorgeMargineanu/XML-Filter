import os
import re
import sys  # Necessary for finding the path when using PyInstaller
import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import filedialog, messagebox, Label
from tkinter import ttk  # Importing ttk for themed widgets
from tkinter.scrolledtext import ScrolledText  # For scrollable text widget
from PIL import Image, ImageTk
from logging import debug
import logging
import time
logger = logging.getLogger(__name__)

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = tk.Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

class XMLFilterApp:
    def __init__(self, master):
        self.master = master
        self.master.title('XML Filter Tool')

        # Use ttk styles
        style = ttk.Style()
        style.configure("TButton", padding=6, relief="flat", background="#ccc")
        style.configure("TLabel", font=("Helvetica", 12))
        style.configure("TFrame", background="#f3f4f6")

        # Main frame for the filters
        main_frame = ttk.Frame(master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        self.label = ttk.Label(main_frame, text='Select XML File:')
        self.label.pack(pady=5)

        self.file_button = ttk.Button(main_frame, text='Browse', command=self.select_file)
        self.file_button.pack(pady=5)

        self.scrollable_frame = ScrollableFrame(main_frame)
        self.scrollable_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        self.run_button = ttk.Button(main_frame, text='Apply Filter', command=self.apply_filter)
        self.run_button.pack(pady=5)

        self.save_button = ttk.Button(main_frame, text='Save Filtered XML', command=self.save_file)
        self.save_button.pack(pady=5)

        self.filepath = ''
        self.elements = set()
        self.attributes = {}
        self.entry_vars = {}

        # Right-side frame to display filtered XML
        right_frame = ttk.Frame(master, padding="10")
        right_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT)

        self.xml_display = ScrolledText(right_frame, wrap=tk.WORD, width=50, height=40)
        self.xml_display.pack(fill=tk.BOTH, expand=True)

        # Define tags for styling
        self.xml_display.tag_configure("tag", foreground="blue")
        self.xml_display.tag_configure("attribute", foreground="green")
        self.xml_display.tag_configure("value", foreground="red")
        self.xml_display.tag_configure("text", foreground="black")

    def select_file(self):
        self.filepath = filedialog.askopenfilename(filetypes=[("XML files", "*.xml")])
        if self.filepath:
            self.label.config(text=f'Selected File: {self.filepath}')
            self.parse_xml()
            self.display_filter_options()
        else:
            self.label.config(text='Select XML File:')

    def parse_xml(self):
        tree = ET.parse(self.filepath)
        root = tree.getroot()

        self.elements = set()  # To hold unique elements
        self.attributes = {}  # To hold unique attributes for each element

        for elem in root.iter():
            self.elements.add(elem.tag)
            if elem.tag not in self.attributes:
                self.attributes[elem.tag] = set()
            for attr in elem.attrib:
                self.attributes[elem.tag].add(attr)

    def display_filter_options(self):
        # Remove existing widgets in the filter frame (if any)
        for widget in self.scrollable_frame.scrollable_frame.winfo_children():
            widget.destroy()

        self.entry_vars = {}

        for element in sorted(self.elements):
            frame = ttk.Frame(self.scrollable_frame.scrollable_frame)
            frame.pack(anchor='w', pady=5)  # Added padding for readability

            var = tk.BooleanVar()
            chk = ttk.Checkbutton(frame, text=f"Element: {element}", variable=var)
            chk.pack(side=tk.LEFT)
            self.entry_vars[element] = {'checkbox': var, 'attributes': {}}

            # Attributes Filtering
            for attr in sorted(self.attributes[element]):
                attr_frame = ttk.Frame(frame)
                attr_frame.pack(anchor='w', pady=2)  # Added padding for readability

                attr_var = tk.BooleanVar()
                attr_chk = ttk.Checkbutton(attr_frame, text=f"Attribute: {attr}", variable=attr_var)
                attr_chk.pack(side=tk.LEFT)

                entry = ttk.Entry(attr_frame)
                entry.pack(side=tk.LEFT, padx=2)
                self.entry_vars[element]['attributes'][attr] = {'checkbox': attr_var, 'entry': entry}

    def apply_filter(self):
        if not self.filepath:
            messagebox.showerror("Error", "Please select an XML file first.")
            return

        tree = ET.parse(self.filepath)
        root = tree.getroot()
        self.saved_tree = ET.Element(root.tag)

        # Helper function to check if any filters are applied
        def filters_applied():
            for tag_vars in self.entry_vars.values():
                if tag_vars['checkbox'].get():
                    return True
                for filter_vars in tag_vars['attributes'].values():
                    if filter_vars['checkbox'].get() and filter_vars['entry'].get():
                        return True
            return False

        def should_append(elem):
            if elem.tag in self.entry_vars:
                tag_vars = self.entry_vars[elem.tag]
                if not tag_vars['checkbox'].get():
                    return False  # Skip if the element itself is not selected

                for attr, filter_vars in tag_vars['attributes'].items():
                    attr_selected = filter_vars['checkbox'].get()
                    attr_value = filter_vars['entry'].get().strip()

                    if attr_selected and attr_value:
                        # Split the input by spaces
                        patterns = attr_value.split()

                        include_patterns = []
                        exclude_patterns = []

                        for pattern in patterns:
                            if pattern.startswith('-'):
                                exclude_patterns.append(pattern[1:])  # Remove the '-' for excluded patterns
                            else:
                                include_patterns.append(pattern)  # Include patterns

                        # Direct exclusion checks
                        attribute_value = elem.attrib.get(attr, '')

                        # Check exclusions first, return False if any matches
                        for exclude_pattern in exclude_patterns:
                            if exclude_pattern in attribute_value:  # Simple substring check
                                return False  # Exclude immediately

                        # Include checks with simple matching
                        if include_patterns:
                            for include_pattern in include_patterns:
                                if include_pattern not in attribute_value:  # Check if any include patterns are not present
                                    return False  # If any pattern isn't found, exclude this element

            return True  # Element passes all checks

        if filters_applied():
            start_time = time.time()
            for elem in root.iter():
                if should_append(elem):
                    self.saved_tree.append(elem)
            end_time = time.time()
            print(f"Filtering completed in {end_time - start_time:.2f} seconds")
        else:
            # If no filters, append all elements
            self.saved_tree = root

        if len(self.saved_tree):
            self.display_filtered_xml()
            messagebox.showinfo("Success", "Filter applied successfully.")
        else:
            self.xml_display.delete(1.0, tk.END)
            messagebox.showinfo("No Results", "No matching results found.")

    def display_filtered_xml(self):
        # Display the filtered XML in the text box with coloring
        self.xml_display.delete(1.0, tk.END)
        xml_str = ET.tostring(self.saved_tree, encoding='utf-8').decode('utf-8')
        self.insert_colored_xml(xml_str)

    def insert_colored_xml(self, xml_str):
        tag_pattern = re.compile(r'(<[^>]+>)')
        attribute_pattern = re.compile(r'(\w+)=(["\'][^"\']*["\'])')
        position = 0

        for match in tag_pattern.finditer(xml_str):
            start, end = match.span()

            # Insert text before the tag if any
            if start > position:
                text = xml_str[position:start]
                self.xml_display.insert(tk.END, text, "text")

            tag_text = match.group(1)

            # Insert the tag with elements colored accordingly
            self.xml_display.insert(tk.END, "<", "tag")
            inner_pos = 1  # Inside tag start after '<'

            for attr_match in attribute_pattern.finditer(tag_text):
                attr_start, attr_end = attr_match.span()
                if attr_start > inner_pos:
                    self.xml_display.insert(tk.END, tag_text[inner_pos:attr_start], "tag")

                attr_name, attr_value = attr_match.groups()
                self.xml_display.insert(tk.END, attr_name, "attribute")
                self.xml_display.insert(tk.END, "=", "tag")
                self.xml_display.insert(tk.END, attr_value, "value")
                inner_pos = attr_end

            if inner_pos < len(tag_text) - 1:
                self.xml_display.insert(tk.END, tag_text[inner_pos:len(tag_text) - 1], "tag")

            self.xml_display.insert(tk.END, ">", "tag")
            position = end

        # Insert any remaining text after the last tag
        if position < len(xml_str):
            self.xml_display.insert(tk.END, xml_str[position:], "text")

    def save_file(self):
        if self.saved_tree is None or len(self.saved_tree) == 0:
            messagebox.showerror("Error", "No filtered data to save.")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".xml", filetypes=[("XML files", "*.xml")])
        if save_path:
            new_tree = ET.ElementTree(self.saved_tree)
            new_tree.write(save_path, encoding='utf-8', xml_declaration=True)
            messagebox.showinfo("Success", f"Filtered XML saved to {save_path}")

if __name__ == "__main__":
    root = tk.Tk()
    root.title("XML Filter")

    # Load the image using the resource path function
    img_path = resource_path('alstom.png')
    img = Image.open(img_path).resize((200, 70), Image.Resampling.LANCZOS)
    tk_img = ImageTk.PhotoImage(img)

    label = Label(root, image=tk_img)
    label.image = tk_img  # Keep a reference to avoid garbage collection
    label.pack(pady=10)  # Added padding for better appearance

    app = XMLFilterApp(root)
    root.mainloop()