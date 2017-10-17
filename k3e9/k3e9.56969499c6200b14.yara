import "hash"

rule k3e9_56969499c6200b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.56969499c6200b14"
     cluster="k3e9.56969499c6200b14"
     cluster_size="27 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['290da978c40845f2175c2f3d743c8643', '25f5103239a6dceb5b29cbe553a7f561', '1f5efa3f074dc5f8fb895e5ae4ccb098']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(7680,1024) == "27a1239f92db79ee8237bfc3250b11a0"
}

