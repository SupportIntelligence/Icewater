import "hash"

rule n3e9_2d151c89c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2d151c89c8000b12"
     cluster="n3e9.2d151c89c8000b12"
     cluster_size="27 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious engine heuristic"
     md5_hashes="['aaf6eeef4d2d0d0c1948706a02c6cdbb', 'e96606aecd7c369d5fd821fa1037dcce', 'cffbc0b8704c744ae61ec44975944923']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(36864,1024) == "17bc42625416a6451d15dc91f0080f23"
}

