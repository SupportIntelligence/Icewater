import "hash"

rule k3e9_1aeb6a48c0001112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1aeb6a48c0001112"
     cluster="k3e9.1aeb6a48c0001112"
     cluster_size="83 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="upatre generickd bublik"
     md5_hashes="['26a88ddc5ec56ebe3e25124875a02fd9', 'cc88884ba0b864a5a6fee529a82f6c6e', 'b04eb71a9fe3d2be736ca120010d4b98']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(11264,1280) == "f29f4417b03a465444d66c200a773784"
}

