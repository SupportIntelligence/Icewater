import "hash"

rule k3e9_3c593ec9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c593ec9c4000b14"
     cluster="k3e9.3c593ec9c4000b14"
     cluster_size="95 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="simbot backdoor razy"
     md5_hashes="['a74597e820a4621f9523f189a98f119c', 'c32f0b47247e37cae53063671632a13a', 'aa195593b635062510a8d3f071071742']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

