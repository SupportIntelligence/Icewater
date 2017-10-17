import "hash"

rule m3e9_53b6bb58dae31b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.53b6bb58dae31b12"
     cluster="m3e9.53b6bb58dae31b12"
     cluster_size="247 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c58d9ac922019e8dd3007748e8b3ce35', 'cdfba483e7f034d89cd5669bc875c04e', 'ab74f04271df0681c34c5a09ff1cebfa']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(80896,1280) == "c23266a7380bf3daa3a8422c6d2fd0c8"
}

