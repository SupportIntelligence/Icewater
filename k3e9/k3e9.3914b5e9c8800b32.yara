import "hash"

rule k3e9_3914b5e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3914b5e9c8800b32"
     cluster="k3e9.3914b5e9c8800b32"
     cluster_size="39 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['abd5a723f8bffc1a2650711ca94fc3ad', 'ae4f532e92ed6f2ece47d2d8159bd2bd', 'ae4f532e92ed6f2ece47d2d8159bd2bd']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(1024,1195) == "482beaebbdc1ed3d7533b440ec3ba87c"
}

