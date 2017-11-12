import "hash"

rule k3e9_51b133169da31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b133169da31b32"
     cluster="k3e9.51b133169da31b32"
     cluster_size="179 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['eec7b6281fab788fd661e31658b6bd10', '811182c2ca90f025e9b9b57c7ad4aece', 'a46d7bf4c7da657cd679103d4909093e']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(22528,1024) == "8013aec142278ae2253a325ded189d2a"
}

