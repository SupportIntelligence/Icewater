import "hash"

rule o3ed_539466c6ce230b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.539466c6ce230b12"
     cluster="o3ed.539466c6ce230b12"
     cluster_size="61 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['3b8014ba45ce52246552ec8fc1ca8409', '6976a421d2fde768a1c563ce54d8aebe', 'd120fb66c4b2b7d5661b74131d2fbbaf']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1692672,1024) == "a8ac4510773e30cb008d5ba614f5bc6a"
}

