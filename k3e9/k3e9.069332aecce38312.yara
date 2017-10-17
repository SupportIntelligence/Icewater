import "hash"

rule k3e9_069332aecce38312
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.069332aecce38312"
     cluster="k3e9.069332aecce38312"
     cluster_size="187 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy tinba injector"
     md5_hashes="['d49e6753024cc2856e2e94da753b8a95', 'c673bef27e48de0faa30d27336bd9d6b', 'b2e457fd0c3a92082e0eebbba572b04d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(51200,1024) == "0b99ab54571122fb1e4adf8e4d2b169b"
}

