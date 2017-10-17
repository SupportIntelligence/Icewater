import "hash"

rule k3e9_6946fa7b61046b96
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6946fa7b61046b96"
     cluster="k3e9.6946fa7b61046b96"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['2d44877548a0f4542748b267d8998d07', '50be6c1907a4796f00513800b7cc5a4f', '2d44877548a0f4542748b267d8998d07']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18723,1041) == "f56d85d5e204fe8b22ff7546c043c8f3"
}

