import "hash"

rule n3fd_4eeb4cbb51e956da
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fd.4eeb4cbb51e956da"
     cluster="n3fd.4eeb4cbb51e956da"
     cluster_size="51 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="expiro xpiro allinone"
     md5_hashes="['decf955237b0b9d1db33cfe331ac371d', '3b33ac728d8e9f3e0fc4d64402231238', '3345089cc65899c418af2cf7d5175ac4']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(774144,1024) == "85e4cef5db11c0c4d93ea2c06234513d"
}

