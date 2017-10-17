import "hash"

rule k3e9_4594d199ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4594d199ca200b12"
     cluster="k3e9.4594d199ca200b12"
     cluster_size="413 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="atraps banload coinbit"
     md5_hashes="['2b9967a61d8a9675ffc8af54577abf25', '7970bff475a296e82b85371f9b8171d3', 'ced2209d89b97f0a9609f9e0cc83621e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,1024) == "952c6324c52fd23be32c5e157819c80e"
}

