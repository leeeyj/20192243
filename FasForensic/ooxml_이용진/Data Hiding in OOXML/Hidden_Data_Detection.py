import binascii
# xml_data = infile.read().decode('utf-8')
        # print(xml_data)
        # if xml_data.find("Ignorable") == -1:
        #     return 0
        # else:
        #     Ignorable_index = xml_data.find("Ignorable")
        # print(xml_data[Ignorable_index+9:])
def parsing(rooxml, fxml, frels):
    with open(rooxml, "rb") as infile:
        buffer = infile.read()
        # print(binascii.hexlify(buffer))

    len_buffer = len(buffer)
    EOCD_offset = len_buffer - 4

    while True:
        if binascii.hexlify(buffer[len_buffer - 4:len_buffer]) != b'504b0506':
            # print(binascii.hexlify(buffer[len_buffer - 4:len_buffer]))
            len_buffer -= 1
            EOCD_offset -= 1
        else:
            len_buffer = len(buffer)
            break

    # print(hex(EOCD_offset))

    CD_Num = int.from_bytes(buffer[EOCD_offset+10:EOCD_offset+12], byteorder="little", signed=False)
    # print("Central Directory 개수:", CD_Num)

    CD_offset = int.from_bytes(buffer[EOCD_offset+16:EOCD_offset+20], byteorder="little", signed=False)
    # print(hex(CD_offset))

    CD = buffer[CD_offset:EOCD_offset]
    LHOL = []
    # LHOL = Local Header offset list

    for i in range(1, CD_Num + 1):
        # print("Central Directory ", i, ":")

        Local_Header_Offset = int.from_bytes(CD[42:46], byteorder='little', signed=False)
        LHOL.append(Local_Header_Offset)

        file_length = int.from_bytes(CD[28:30], byteorder='little', signed=False)
        extra_field_length = int.from_bytes(CD[30:32], byteorder='little', signed=False)
        file_comment_length = int.from_bytes(CD[32:34], byteorder='little', signed=False)
        file_name = CD[46:46 + file_length]
        # print(file_name[len(file_name)-3:].decode('euc-kr'))
        # print("파일 이름: ", file_name.decode('euc-kr'), '\n')
        if file_name[len(file_name)-3:].decode('euc-kr') == 'xml':
            fxml.append(file_name.decode('euc-kr'))
        elif file_name[len(file_name)-4:].decode('euc-kr') == 'rels':
            frels.append(file_name.decode('euc-kr'))

        # f = open("C:/Users/LeeYongJin/Desktop/Fas_Forensic/210129_FaS 과제/ppt2.txt", 'a')
        # f.write(file_name.decode('euc-kr')+'\n')
        CD = CD[46 + file_length + extra_field_length + file_comment_length:]


def find_Ignorable_attribute(xml):
    with open(xml, "rb") as infile:
        while True:
            line = infile.readline().decode('utf-8')
            if line.find("Ignorable") != -1:
                Ignorable = line[line.index("Ignorable=")+11:line.index(">")-1]
                return Ignorable
            elif not line:
                # print("This xml file doesn't have Ignorable Attribute\n")
                return 0

def find_Hidden_Data_rId(xml ,Ignorable):
    with open(xml, "rb") as infile:
        Ignorable_attribute1 = "<" + Ignorable
        Ignorable_attribute2 = "</" + Ignorable
        xml_data = infile.read().decode('utf-8')

        meta_data_sindex = xml_data.find(Ignorable_attribute1)
        meta_data_eindex = xml_data.find(Ignorable_attribute2)

        meta_data = xml_data[meta_data_sindex:meta_data_eindex]
        # print(meta_data)
        meta_data = meta_data[meta_data.find("rId"):]
        rId = meta_data[:meta_data.find(">")-1]
        return rId

def find_Hidden_Data(rels, rId):
    with open(rels, "rb") as infile:
        rels_data = infile.read().decode('utf-8')
        rels_data = rels_data[rels_data.find(rId):]
        Target = rels_data[rels_data.find("Target"):rels_data.find("/>")]
        print("rId = ", rId)
        print(Target)



read_ooxml = "C:/Users/LeeYongJin/Desktop/Fas_Forensic/example2.pptx"
find_xml_file = []
find_rels_file = []
parsing(read_ooxml, find_xml_file, find_rels_file)

for i in range(0, len(find_xml_file)):
    xml_file = "C:/Users/LeeYongJin/Desktop/Fas_Forensic/example2/example2/" + find_xml_file[i]
    find_Ignorable_attribute(xml_file)
    if find_Ignorable_attribute(xml_file) != 0:
        print("\n"+find_xml_file[i])
        print("This xml file has Ignorable Attribute\n")

        find_Hidden_Data_rId(xml_file, find_Ignorable_attribute(xml_file))

        rels_file = "C:/Users/LeeYongJin/Desktop/Fas_Forensic/example2/example2/ppt/slides/_rels/slide2.xml.rels"
        find_Hidden_Data(rels_file, find_Hidden_Data_rId(xml_file, find_Ignorable_attribute(xml_file)))