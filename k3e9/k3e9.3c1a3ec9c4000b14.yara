import "hash"

rule k3e9_3c1a3ec9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1a3ec9c4000b14"
     cluster="k3e9.3c1a3ec9c4000b14"
     cluster_size="424 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['b61bbfcf0925ddd150e85a15284034d2', 'c2833b642e37f7c19e84d1434ee7d317', 'a2e22ebc4f2a409feb15f460a38b2917']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

