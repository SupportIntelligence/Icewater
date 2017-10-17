import "hash"

rule o3ed_539446c6ee210912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.539446c6ee210912"
     cluster="o3ed.539446c6ee210912"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['ce266154bc7568e0e7db6e6339475f6e', '242564e007dd89998f054423998411f7', '242564e007dd89998f054423998411f7']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1692672,1024) == "a8ac4510773e30cb008d5ba614f5bc6a"
}

