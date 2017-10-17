import "hash"

rule k3e9_6b64d34b9b2b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b9b2b5912"
     cluster="k3e9.6b64d34b9b2b5912"
     cluster_size="227 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['cda613e0ceffbc3a2c5598687940b76f', 'cda613e0ceffbc3a2c5598687940b76f', 'a1e44b50c781702cc1eb748fbf35f0b5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20684,1036) == "c385819817add297b9d954ae7b0d57d4"
}

