import "hash"

rule m3e9_46b48669dad31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.46b48669dad31912"
     cluster="m3e9.46b48669dad31912"
     cluster_size="43 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="skintrim dialer instantaccess"
     md5_hashes="['e14dcaf06aeb0e53b103461d05383388', 'c126070f0d76cf4afe055ca60284c912', 'd3e0837e3a40384cc06f7cee51c1ae96']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(103424,1024) == "b1fe8f27dd245bf2aa7ba834015fa9b7"
}

