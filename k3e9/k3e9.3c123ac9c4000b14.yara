import "hash"

rule k3e9_3c123ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c123ac9c4000b14"
     cluster="k3e9.3c123ac9c4000b14"
     cluster_size="285 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['cb3d064312c8466b9d6894e9e7a62e70', 'ab387d7ad36ef5499a09245bb1cd2823', 'c3c58f6c2e55e6419a25d5b65e86f3db']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

