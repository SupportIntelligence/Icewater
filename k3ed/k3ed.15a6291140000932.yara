import "hash"

rule k3ed_15a6291140000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.15a6291140000932"
     cluster="k3ed.15a6291140000932"
     cluster_size="340 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious proxy heuristic"
     md5_hashes="['895b9751bb9142386ae4b8a6c07a31c1', '2a78738c9ae13e0fa02ee1b1954dc95a', '1e250c9e0077f239f82eac4b37de8995']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17920,1024) == "aae49529e8e9767c6cdd3fa7a6b0b1a5"
}

