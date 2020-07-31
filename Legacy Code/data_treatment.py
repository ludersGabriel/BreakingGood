from termcolor import colored
import os, sys

class data_manager:
    ext1 = ".byte"
    ext2 = ".string"
    ext3 = ".vt" #file with the api call results
    ext4 = ".swap"
    ext5 = ".addSub"
    ext6 = ".gwa"
    treatmentExt = "det"
     
    def __init__(self, temp_dir, ncolor, nprint):
        self.temp_dir = temp_dir
        self.ncolor = ncolor
        self.nprint = nprint
    
    def open_file(self, name, mode):
        file = open(name, mode)
        if file.closed:
            print("Could not open {name}".format(name=name))
            sys.exit(1)
        return file

    def get_dict(self, file):
        dic_file = self.open_file(file, "r")
        s = dic_file.read()
        s = s.replace("false", "False")
        s = s.replace("true", "True")
        s = s.replace("null", "None")
        dic_file.close()
        dic = eval(s) 
        return dic

    def set_color(self, string):
        if string == "False":
            string = colored("{:<10}", "red").format(string)
        else:
            string = colored("{:<10}", "green").format(string)
        return string

    def detection_table(self):
        #gets all the files in a folder
        files = os.popen("ls {folder}".format(folder=self.temp_dir)).read()
        files = list(files.split("\n"))
        del files[len(files) - 1]

        #getting unique hash names
        hashes = []
        for file in files:
            hash_name = list(file.split("."))[0]
            if not hash_name in hashes:
                hashes.append(hash_name) 

        for hash_name in hashes:
            name = "{dir}/{name}.{extension}".format(dir=self.temp_dir, name=hash_name, extension=self.treatmentExt)
            det_file = self.open_file(name, "x")
            print("\nSample: {name}".format(name=hash_name))
            header = "{:<25} {:<10} {:<10} {:<10} {:<10} {:<10} {:<10}\n".format("AV", "ORIG", "BYTES", "STR", "SWAP", "ADD_SUB", " GWA")
            det_file.write(header)
            if not self.nprint:
                print(header)
            
            byte_name = "{dir}/{name}".format(dir=self.temp_dir, name=hash_name + self.ext1 + self.ext3)
            byte_dic = self.get_dict(byte_name)
            string_name = "{dir}/{name}".format(dir=self.temp_dir, name=hash_name + self.ext2 + self.ext3)
            string_dic = self.get_dict(string_name)
            original_name = "{dir}/{name}".format(dir=self.temp_dir, name=hash_name + ".original" + self.ext3)
            original_dic = self.get_dict(original_name)
            swap_name = "{dir}/{name}".format(dir=self.temp_dir, name=hash_name + self.ext4 + self.ext3)
            swap_dic = self.get_dict(swap_name)
            addSub_name = "{dir}/{name}".format(dir=self.temp_dir, name=hash_name + self.ext5 + self.ext3)
            addSub_dic = self.get_dict(addSub_name)
            gwa_name = "{dir}/{name}".format(dir=self.temp_dir,name=hash_name + self.ext6 + self.ext3)
            gwa_dic = self.get_dict(gwa_name)
            
            for av in byte_dic["scans"]:
                try:
                    orig_det = str(original_dic["scans"][av]["detected"])
                    if not self.ncolor:
                        orig_det = self.set_color(orig_det)
                except KeyError:
                    orig_det = "-"

                try:
                    byte_det = str(byte_dic["scans"][av]["detected"])
                    if not self.ncolor:
                        byte_det = self.set_color(byte_det) 
                except KeyError:
                    byte_det = "-"

                try:
                    str_det = str(string_dic["scans"][av]["detected"]) 
                    if not self.ncolor:
                        str_det = self.set_color(str_det)
                except KeyError:
                    str_det = "-"

                try:
                    swap_det = str(swap_dic["scans"][av]["detected"]) 
                    if not self.ncolor:
                        swap_det = self.set_color(swap_det)
                except KeyError:
                    swap_det = "-"

                try:
                    addSub_det = str(addSub_dic["scans"][av]["detected"]) 
                    if not self.ncolor:
                        addSub_det = self.set_color(addSub_det)
                except KeyError:
                    addSub_det = "-"    
                
                try:
                    gwa_det = str(gwa_dic["scans"][av]["detected"]) 
                    if not self.ncolor:
                        gwa_det = self.set_color(gwa_det)
                except KeyError:
                    gwa_det = "-"

                data_string = "{:<25} {:<10} {:<10} {:<10} {:<10} {:<10} {:<10}\n".format(av, orig_det, byte_det, str_det, swap_det, addSub_det, gwa_det)
                det_file.write(data_string)
                if not self.nprint:
                    print(data_string)

            det_file.close()
