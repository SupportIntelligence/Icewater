import "hash"

rule o3e9_19124a90ddeb4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.19124a90ddeb4912"
     cluster="o3e9.19124a90ddeb4912"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious noobyprotect webalta"
     md5_hashes="['4a1f8f03d24e18294137ad54cc6bcaad', 'b1016374ed337b6c737d7cddbc28536f', 'a399fb78dd4f1fe82cde2d2a8b9f83dd']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2973696,1024) == "c593ac4efbaf856836eda4ebec5d9635"
}

