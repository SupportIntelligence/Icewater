import "hash"

rule o3e9_16d348c6d692699a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.16d348c6d692699a"
     cluster="o3e9.16d348c6d692699a"
     cluster_size="538 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['802b7e7f3943d1723feec03a7fe9b2fa', '6eb8e56b91212f7c9c17d8b03c8a829f', '097fec9ada4f0957cea283dee67a03f7']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1784320,1024) == "b1ac007303f77b2ddd946181deba8128"
}

