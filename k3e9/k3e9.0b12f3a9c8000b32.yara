import "hash"

rule k3e9_0b12f3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b12f3a9c8000b32"
     cluster="k3e9.0b12f3a9c8000b32"
     cluster_size="17 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy backdoor injector"
     md5_hashes="['10042ddb09663b135f17e1be27e28d0b', 'c0d87caee664136c976b911350134d89', 'a72dc0ab58e534ee6d9f1d721bfcfa5d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

