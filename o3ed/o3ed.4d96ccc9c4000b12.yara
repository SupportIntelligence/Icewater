import "hash"

rule o3ed_4d96ccc9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.4d96ccc9c4000b12"
     cluster="o3ed.4d96ccc9c4000b12"
     cluster_size="215 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['e0364ddf9c8200aeef5f778f18a2194e', 'cf59bb3a941181b45364b12aef36c144', 'd46b84a517a61a1b97c42cbb7479313d']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1090560,1024) == "911c2f8501f8e0e5dee0dd35e6ef1f93"
}

