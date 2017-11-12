import "hash"

rule k3e9_091ff3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.091ff3e9c8000b12"
     cluster="k3e9.091ff3e9c8000b12"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy backdoor simbot"
     md5_hashes="['b2a84d0e85864438321a1550de3bc5a8', 'b2a84d0e85864438321a1550de3bc5a8', '3d851720e1c32bd6107136ea96529ecc']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

