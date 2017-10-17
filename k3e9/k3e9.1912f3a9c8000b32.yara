import "hash"

rule k3e9_1912f3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1912f3a9c8000b32"
     cluster="k3e9.1912f3a9c8000b32"
     cluster_size="33 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy injector backdoor"
     md5_hashes="['ba937a5e8e0f6e804058b86ec530b9cf', 'b50c3d1ce3cfc226edf71dd1ca2a8811', 'd7e84c4c4d7411c6b846d712f1a06071']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

