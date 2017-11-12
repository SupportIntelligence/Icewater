import "hash"

rule k3e9_391c91e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391c91e9c8800b32"
     cluster="k3e9.391c91e9c8800b32"
     cluster_size="119 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['4ff99f1a8dbdd2e15c16601fae64e8e9', 'a2d460695d11aa6ee060b512047a5870', 'd83ceaa1727a5d53ba039ee4426cf8f8']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(1024,1195) == "482beaebbdc1ed3d7533b440ec3ba87c"
}

