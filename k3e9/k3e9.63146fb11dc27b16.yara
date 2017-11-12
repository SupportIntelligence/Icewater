import "hash"

rule k3e9_63146fb11dc27b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fb11dc27b16"
     cluster="k3e9.63146fb11dc27b16"
     cluster_size="249 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['db3cde13a79ce9e1c40e0caa41ae61c7', 'bc0bb2bf8a30837ead98464d6cba10a7', 'a3cd692d9646001ed1c7366b9bc519bf']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

