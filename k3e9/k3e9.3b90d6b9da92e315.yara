import "hash"

rule k3e9_3b90d6b9da92e315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b90d6b9da92e315"
     cluster="k3e9.3b90d6b9da92e315"
     cluster_size="89 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['d84d34e8cdc5c1b3d6dd8127b878746f', '2b580d1c1bc5b23046fe4953a59d51c6', 'b85d6a10c6afa1104042851ae3aaccea']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15360,1024) == "3841de42f0286b52362adefe8684af6f"
}

