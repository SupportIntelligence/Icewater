import "hash"

rule k3e9_63146fb119926b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fb119926b16"
     cluster="k3e9.63146fb119926b16"
     cluster_size="134 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['7f158d62f26eea5fb6ff659afc0282c8', 'd81f6ef409d4c5448c21e2703b21d186', 'a463e5c22471068cd590014b4824f530']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

