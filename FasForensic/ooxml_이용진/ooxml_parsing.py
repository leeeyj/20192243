# ================================================================
#
# author: 국민대학교 정보보안암호수학과 20192243 이용진
# Kookmin Univ. Information security math & cryptography
#
# Team: Fas_Forensic
#
# Project : Develop ooxml parsing program
#
# Date : 2021.2.3 ~
# ================================================================

# 핵심 xml : core.xml, app.xml, presentation.xml, presentation.xml

def parsing_Content_type_xml(ppt_content_type_xml):
    with open(ppt_content_type_xml, "rb") as infile:
        print("\n===== Parts in [Content_Types].xml =====")
        Content_Type_xml = infile.read().decode('UTF-8')

        Part = Content_Type_xml.count('PartName')
        print("Number of Parts = ", Part)
        # 패키지에 사용하는 Part의 개수 찾기

        Part_index = Content_Type_xml.index('PartName')+9
        # Part 이름 시작 index 찾기

        PartName = Content_Type_xml[Part_index:]
        # PartName 을 포함하는 배열

        # PartName 을 출력하는 코드
        for i in range(0, Part):
            if i == Part-1:
                PartName = PartName[0:PartName.find('xml"') + 4]
                print(PartName)
                break

            Part_index += PartName.index('PartName') + 9
            PartName = PartName[0:PartName.find('xml"') + 4]
            print(PartName)
            PartName = Content_Type_xml[Part_index:]

        print("========================================")


def parsing_core_xml(ppt_core_xml):
    with open(ppt_core_xml, "rb") as infile:
        print("\n=============== core.xml ===============")

        Core_xml = infile.read().decode('UTF-8')

        Title = Core_xml[Core_xml.index("<dc:title>") + 10:Core_xml.index('</dc:title>')]
        print("Title : ",Title)

        Creator = Core_xml[Core_xml.index("<dc:creator>") + 12:Core_xml.index('</dc:creator>')]
        print("Creator : ", Creator)

        LastModifiedBy = Core_xml[Core_xml.index("<cp:lastModifiedBy>") + 19:Core_xml.index('</cp:lastModifiedBy>')]
        print("Last Modified By : ", LastModifiedBy)

        Revision = Core_xml[Core_xml.index("<cp:revision>") + 13:Core_xml.index('</cp:revision>')]
        print("Revision : ", Revision) # 수정 횟수

        Created_time = Core_xml[Core_xml.index("<dcterms:created") + 43:Core_xml.index('</dcterms:created>')]
        print("Created Time : ", Created_time)

        Modified_time = Core_xml[Core_xml.index("<dcterms:modified") + 44:Core_xml.index('</dcterms:modified>')]
        print("Modified Time : ", Modified_time)

        print("========================================")

def parsing_app_xml(ppt_app_xml):
    with open(ppt_app_xml, 'rb') as infile:
        print("\n=============== app.xml ================")

        App_xml = infile.read().decode('UTF-8')

        Total_time = App_xml[App_xml.index('<TotalTime>')+11:App_xml.index('</TotalTime>')]
        print("Total Time : ", Total_time, "분") # 총 편집시간

        Words = App_xml[App_xml.index('<Words>')+7:App_xml.index('</Words>')]
        print("Words : ", Words)

        Application = App_xml[App_xml.index('<Application>')+13:App_xml.index('</Application>')]
        print("Application : ", Application)

        Paragraphs = App_xml[App_xml.index('<Paragraphs>')+12:App_xml.index('</Paragraphs>')]
        print("Paragraphs : ", Paragraphs)

        Slides = App_xml[App_xml.index('<Slides>')+8:App_xml.index('</Slides>')]
        print("Slides : ", Slides)

        Notes = App_xml[App_xml.index('<Notes>')+7:App_xml.index('</Notes>')]
        print("Notes : ", Notes)

        Hidden_slides = App_xml[App_xml.index('<HiddenSlides>')+14:App_xml.index('</HiddenSlides>')]
        print("Hidden Slides : ", Hidden_slides)

        print("========================================")


def parsing_Presentation_xml(ppt_presentation_xml):
    with open(ppt_presentation_xml, 'rb') as infile:
        print("\n=========== presentation.xml ===========")

        Presentation_xml = infile.read().decode('UTF-8')
        Slide_Id_List = Presentation_xml[Presentation_xml.index('<p:sldIdLst>')+12:Presentation_xml.index('</p:sldIdLst>')]
        Slide_Id_List_num = Slide_Id_List.count('rId')

        print("Number of Slide Id List : ", Slide_Id_List_num)
        # 사용된 슬라이드의 리스트의 개수를 출력

        # 사용된 슬라이드의 Id를 출력
        for i in range(1, Slide_Id_List_num+1):
            Slide = Slide_Id_List
            Slide_Id = Slide[Slide.index(' id') + 1:Slide.index('/>')-1]
            Slide_Id_List = Slide_Id_List[Slide.index('/>')+2:]
            print("Slide ID : ", Slide_Id)

        print("========================================")


read_ppt1_content_type_xml = "C:/Users/LeeYongJin/Desktop/Fas_Forensic/210129_FaS 과제/ppt1/[Content_Types].xml"
read_ppt1_core_xml = "C:/Users/LeeYongJin/Desktop/Fas_Forensic/210129_FaS 과제/ppt1/docProps/core.xml"
read_ppt1_app_xml = "C:/Users/LeeYongJin/Desktop/Fas_Forensic/210129_FaS 과제/ppt1/docProps/app.xml"
read_ppt1_presentation_xml = "C:/Users/LeeYongJin/Desktop/Fas_Forensic/210129_FaS 과제/ppt2/ppt/presentation.xml"


parsing_Content_type_xml(read_ppt1_content_type_xml)
parsing_core_xml(read_ppt1_core_xml)
parsing_app_xml(read_ppt1_app_xml)
parsing_Presentation_xml(read_ppt1_presentation_xml)