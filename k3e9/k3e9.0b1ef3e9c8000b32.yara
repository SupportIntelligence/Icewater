import "hash"

rule k3e9_0b1ef3e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b1ef3e9c8000b32"
     cluster="k3e9.0b1ef3e9c8000b32"
     cluster_size="72 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy backdoor simbot"
     md5_hashes="['c27bb0098bc1dba00c18d103c7e152d2', '36515de22040889350f0a2eb7c5a0653', 'd3178b2695a751df66ef1dc5899f8c64']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

