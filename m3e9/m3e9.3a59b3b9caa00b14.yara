import "hash"

rule m3e9_3a59b3b9caa00b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a59b3b9caa00b14"
     cluster="m3e9.3a59b3b9caa00b14"
     cluster_size="529 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="otwycal wapomi vjadtre"
     md5_hashes="['8a87fc2b3bbecaae9cceb0870b4f50b7', '53f9fea051b827a9f93dbe3e42ebd938', 'a6b48e03ca1a32164371c9c0515f8701']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

