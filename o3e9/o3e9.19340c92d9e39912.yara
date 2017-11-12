import "hash"

rule o3e9_19340c92d9e39912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.19340c92d9e39912"
     cluster="o3e9.19340c92d9e39912"
     cluster_size="562 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy malicious noobyprotect"
     md5_hashes="['286eea1ad70bc45438001d9e928d3e99', '65ad4db67c2fab42318239f40dec8590', '766151200bbe51c94bd1a12fd837183d']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3062784,1024) == "3fe8ee633ca02164c03a78cdd753a45f"
}

