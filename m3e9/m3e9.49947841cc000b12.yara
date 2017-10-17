import "hash"

rule m3e9_49947841cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.49947841cc000b12"
     cluster="m3e9.49947841cc000b12"
     cluster_size="30 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['6be64782379f413907755db902595bf2', '37f3596ca47416d1892881291e018259', '74a8c363f7bd87bb3225e8b4f5c02f6f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(47104,1024) == "f7b221558b148f5f55ad23ea9cac0d8c"
}

