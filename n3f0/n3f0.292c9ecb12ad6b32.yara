import "hash"

rule n3f0_292c9ecb12ad6b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.292c9ecb12ad6b32"
     cluster="n3f0.292c9ecb12ad6b32"
     cluster_size="1249 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="amonetize malicious bundler"
     md5_hashes="['2401af23d9bbca6c87de0376d3214cc3', '350b3c733d742d794e905b7ca541634b', '3492ea209a59deb983c4af3336d506f6']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(237978,1126) == "99d264b9fe8ab7dcfcb98dd2c4dd55ae"
}

