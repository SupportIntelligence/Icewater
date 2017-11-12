import "hash"

rule k3e9_45b4fc269bbb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45b4fc269bbb1932"
     cluster="k3e9.45b4fc269bbb1932"
     cluster_size="38 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['82861803aeb8b505a83e563007ccdd6a', 'd04966fee8321ba70e4f20c80dc8a33f', '3f7aa3a27443f50e91012cfa9566cf73']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(20480,1280) == "3e6f4cfcf731d063cebc1073d9d20cf0"
}

