import "hash"

rule k3e9_3c19a848c0010b10
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c19a848c0010b10"
     cluster="k3e9.3c19a848c0010b10"
     cluster_size="107 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zbot upatre generickd"
     md5_hashes="['b4fd09cd4bab864acbcbb633db55fe21', '4bb00afaa3b4932544bab8a40e431d90', 'e8be9ed76821cd92b950f64754eba90f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "9fa1d766c4dc195888a12c0d4c7c1e53"
}

