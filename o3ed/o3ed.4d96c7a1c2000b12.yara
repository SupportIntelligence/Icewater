import "hash"

rule o3ed_4d96c7a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.4d96c7a1c2000b12"
     cluster="o3ed.4d96c7a1c2000b12"
     cluster_size="52 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['cdf94e8d6cfdf215495121ab5da41c0f', '188b915f4eb9759d8ee0704f1bb08f8e', '188b915f4eb9759d8ee0704f1bb08f8e']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1173504,1024) == "79a0ca033e9476bdf570bdd896445f12"
}

