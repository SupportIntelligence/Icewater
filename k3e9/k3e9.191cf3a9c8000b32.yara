import "hash"

rule k3e9_191cf3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.191cf3a9c8000b32"
     cluster="k3e9.191cf3a9c8000b32"
     cluster_size="335 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor razy injector"
     md5_hashes="['12e28692f9ccb5ca9586287e8dac0b41', 'a2155aedf3d972d46649eddc048af96c', 'bf44fef028291d6832ffdb25a76b98bc']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

