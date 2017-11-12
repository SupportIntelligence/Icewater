import "hash"

rule k3e9_05355856dabb0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.05355856dabb0932"
     cluster="k3e9.05355856dabb0932"
     cluster_size="32 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['0c607a5a8635f951b9376154a80fb8e2', 'b7de19ceed7f2940ac6831b636dbae43', 'b33f601c9599cec53019d49626b922f4']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(17408,1024) == "0fe9e98508ccf8e184d819bf21b5ad2b"
}

