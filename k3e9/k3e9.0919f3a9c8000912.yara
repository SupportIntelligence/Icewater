import "hash"

rule k3e9_0919f3a9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0919f3a9c8000912"
     cluster="k3e9.0919f3a9c8000912"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy injector backdoor"
     md5_hashes="['a64175d8eb4010248e082f226b7dd88e', 'c7ee5d13aceb8958732fd6e53743983c', 'a64175d8eb4010248e082f226b7dd88e']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

