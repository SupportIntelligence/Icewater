import "hash"

rule n3e9_0b1236b6d7bb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b1236b6d7bb1932"
     cluster="n3e9.0b1236b6d7bb1932"
     cluster_size="39 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="foax kryptik malicious"
     md5_hashes="['47e50c84aabf0322733a2060e14ca187', '2dc15f4d50ca13f4002d384d41b87260', '6ba595856c5fda9a350bc8e2d2514268']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(647168,1024) == "5871d25b2156944140f121c756cf1c6b"
}

