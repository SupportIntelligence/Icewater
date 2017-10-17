import "hash"

rule o3e9_4d66ea49c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.4d66ea49c0000932"
     cluster="o3e9.4d66ea49c0000932"
     cluster_size="7855 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious startpage adsearch"
     md5_hashes="['020b76b617527696e70caf16195477f0', '05791a35e8dbde8ea82d02b68ef24413', '037d9034480c425c76b18729e9798ae9']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(350355,1097) == "52333db0b7cb10c0279fa87ecebc4a13"
}

