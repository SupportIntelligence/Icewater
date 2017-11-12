import "hash"

rule j3e9_44548998dee30a80
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.44548998dee30a80"
     cluster="j3e9.44548998dee30a80"
     cluster_size="204 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="chir nimda runouce"
     md5_hashes="['7877838c92bb55873fdd32b7c7d554f3', 'f8b7c7681e3b555a15fc2769aab98e1b', 'a6ea63657f39baf3eccf9a4dca66e3e6']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(5266,1097) == "b1d6b9b43348eee21b43c6f2b7283037"
}

