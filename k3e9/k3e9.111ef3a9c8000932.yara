import "hash"

rule k3e9_111ef3a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.111ef3a9c8000932"
     cluster="k3e9.111ef3a9c8000932"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy backdoor injector"
     md5_hashes="['dc7fa0b8fd7c78e1315bc7395b142a5a', 'cba1b943400af76ebd390bcabfd0dab4', 'cba1b943400af76ebd390bcabfd0dab4']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

