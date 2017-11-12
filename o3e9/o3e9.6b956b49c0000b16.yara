import "hash"

rule o3e9_6b956b49c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6b956b49c0000b16"
     cluster="o3e9.6b956b49c0000b16"
     cluster_size="361 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor trojandropper malicious"
     md5_hashes="['61b31aed865bc9b0c97dec512d131a99', '19861e3b67b0e7935044a7818815b6a8', '37b7557c79c86a5515a170dc22075e60']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(138262,1046) == "66a1aad2b922cc836352280ff4cf1d3b"
}

