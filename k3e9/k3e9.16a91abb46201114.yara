import "hash"

rule k3e9_16a91abb46201114
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.16a91abb46201114"
     cluster="k3e9.16a91abb46201114"
     cluster_size="552 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="kazy rubinurd small"
     md5_hashes="['b2863e5e305e8f56a9dd5987e99029e6', 'cbfb91065e122f35d3a6ca36844a763b', 'aca3f64b13526a3682e71d3d5b5aa806']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "2b75e03ba80408ac5917d1e4af2d3085"
}

