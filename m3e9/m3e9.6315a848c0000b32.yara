import "hash"

rule m3e9_6315a848c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6315a848c0000b32"
     cluster="m3e9.6315a848c0000b32"
     cluster_size="47 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171018"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['ebef0a42b7b8f0e65300b47a62078ac1', 'ebef0a42b7b8f0e65300b47a62078ac1', '374066e4711709d1a682448a5016051e']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(57856,1024) == "75f3c9fd975d819550e3e61fa3b0e2b0"
}

