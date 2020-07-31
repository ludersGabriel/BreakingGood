from termcolor import colored
import os, sys, argparse

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

    def get_files(self):
        lsFiles = os.popen("ls {folder}".format(folder=self.temp_dir)).read()
        lsFiles = list(lsFiles.split("\n"))
        del lsFiles[len(lsFiles) - 1]

        files = []
        for file in lsFiles:
            if list(file.split(".")).count("vt"):
                files.append(file)
        return files

    def get_hash_names(self, files):
        hashes = []
        for file in files:
            hash_name = list(file.split("."))[0]
            if not hash_name in hashes:
                hashes.append(hash_name)
        return hashes

    def get_extensions(self, files):
        extensions = []
        for file in files:
            ext = file.split(".")[1]
            if ext != "original":
                extensions.append(ext)
        return extensions

    def get_header(self, extensions):
        header = "{:<25} {:<10}".format("AV", "ORIG")
        for ext in extensions:
            string = " {:<10}".format(ext.upper())
            header = header + string
        header = header
        return header

    def get_all_dic(self, hash_name, extensions):
        vtDicts = []
        name = "{dir}/".format(dir=self.temp_dir) + hash_name + ".original.vt"
        dic = self.get_dict(name)
        vtDicts.append(dic)
        for ext in extensions:
            name = "{dir}/".format(dir=self.temp_dir) + hash_name + "." + ext + ".vt"
            dic = self.get_dict(name)
            vtDicts.append(dic)
        return vtDicts

    def detection_table(self):
        files = self.get_files()
        hashes = self.get_hash_names(files)
        ext = self.get_extensions(files)

        for hash_name in hashes:
            name = "{dir}/{name}.{extension}".format(dir=self.temp_dir, name=hash_name, extension=self.treatmentExt)
            det_file = self.open_file(name, "x")
           
            header = self.get_header(ext)
            det_file.write(header)
            if not self.nprint:
                print("\n(MD5): {name}".format(name=hash_name))
                print(header)
            
            vtDicts = self.get_all_dic(hash_name, ext)
            
            # index 0 marks the original file
            for av in vtDicts[0]["scans"]:
                data_string = "{:<25}".format(av)
                for dic in vtDicts:
                    aux = ""
                    try:
                        aux = str(dic["scans"][av]["detected"])
                        if not self.ncolor:
                            aux = self.set_color(aux)
                    except KeyError:
                        aux = "-"

                    aux = " {:<10}".format(aux)
                    data_string = data_string + aux

                det_file.write(data_string)
                if not self.nprint:
                    print(data_string)

            det_file.close()
