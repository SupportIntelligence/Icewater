import "hash"

rule m3e9_519bb60dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.519bb60dc6220b32"
     cluster="m3e9.519bb60dc6220b32"
     cluster_size="163 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['36f2ce3bd135404f4b25e2bac40507db', 'cbc8d305182aacbd87e6a80ab390742f', 'cbc8d305182aacbd87e6a80ab390742f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64000,1024) == "3a2b8b8e8c5ba0975f11e47f5b4896fd"
}

