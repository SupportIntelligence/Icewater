import "hash"

rule k3e9_3c1a7ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1a7ac9c4000b14"
     cluster="k3e9.3c1a7ac9c4000b14"
     cluster_size="252 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['bacf26f6cd96426db2a06b3b49fca454', 'aa30ca0dd45102c56159b0f9ce7d947e', 'a10a16b523856cb8e851c93c476b089c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

