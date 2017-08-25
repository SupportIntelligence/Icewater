import "hash"

rule m3f4_11584972d882fb12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f4.11584972d882fb12"
     cluster="m3f4.11584972d882fb12"
     cluster_size="612 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="backdoor nanocore noancooe"
     md5_hashes="['4e6a1c62af165f6457b6a80d84e1195f', '2a06000b8609822672eb8a856189b83d', '6ebc46ea0bf3391d224f1d77f579eaed']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(99840,1024) == "b7b7780a7488ec74afdab839017db84b"
}

