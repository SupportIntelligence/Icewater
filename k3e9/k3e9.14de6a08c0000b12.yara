import "hash"

rule k3e9_14de6a08c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.14de6a08c0000b12"
     cluster="k3e9.14de6a08c0000b12"
     cluster_size="477 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bublik generickd upatre"
     md5_hashes="['bfdbbefc2e119179004ae667f5775189', 'd1c58d3049042f71ae90adfd39a4ffad', 'c8723410c2a7340664c64d0906eb29cd']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(10240,1024) == "e9ef99084fe7ea6663f195e04859d720"
}

