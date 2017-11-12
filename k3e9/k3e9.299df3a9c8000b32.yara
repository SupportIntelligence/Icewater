import "hash"

rule k3e9_299df3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.299df3a9c8000b32"
     cluster="k3e9.299df3a9c8000b32"
     cluster_size="77 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy backdoor injector"
     md5_hashes="['c0b655d74f098996fc5083e57b14ab32', 'cc2c97cffb83e9e2cdae5fa2a618a674', '4db09a5f9fbfc5ea4b8991801dff3120']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

