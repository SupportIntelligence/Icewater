import "hash"

rule n3e9_0b123284d3bb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b123284d3bb1912"
     cluster="n3e9.0b123284d3bb1912"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="fvyj kryptik malicious"
     md5_hashes="['b9c9ec7198342c55ae72474317188e99', '277f8b505ac4bedabfa54d6659746bb3', 'b9c9ec7198342c55ae72474317188e99']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(647168,1024) == "2a3cbe28e9575b0e98b3d828a8cbed73"
}

