import "hash"

rule m3f4_11584972d882fb12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f4.11584972d882fb12"
     cluster="m3f4.11584972d882fb12"
     cluster_size="625 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="backdoor nanocore noancooe"
     md5_hashes="['07b573335ba50a14e7882f2344108aeb', '70d883874846817f7d2931c6c5212b5b', '053c91d9e38322fb673a6dd006eb14e8']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(99840,1024) == "b7b7780a7488ec74afdab839017db84b"
}

