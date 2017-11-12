import "hash"

rule m3f0_51a2d587ea221112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.51a2d587ea221112"
     cluster="m3f0.51a2d587ea221112"
     cluster_size="8957 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="kryptik gepys bcig"
     md5_hashes="['1fe953473692a5baa9ba3a95a3cfe5d7', '1293da8ddd64af43fb52174244154ec4', '17abd4aaadcda49dbafb0bd40ff94b76']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(131072,1024) == "750e8917afbd19751811b489e0ae951d"
}

