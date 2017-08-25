import "hash"

rule m3e9_0da18a41229dcb36
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0da18a41229dcb36"
     cluster="m3e9.0da18a41229dcb36"
     cluster_size="14623 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="cripack yakes tpyn"
     md5_hashes="['0208940a10c2116bdff4d19e6d0bfc9a', '02dc2ff5b7252ab89933acbbaeb3c66b', '02e7cfa17f64118c25fb36e734979ca3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(200704,1024) == "efe51f39a80cfc23604bc52aecaac148"
}

