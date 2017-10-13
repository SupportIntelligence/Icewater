import "hash"

rule m3e9_681cbab9ca200b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.681cbab9ca200b32"
     cluster="m3e9.681cbab9ca200b32"
     cluster_size="842 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="symmi vbkrypt injector"
     md5_hashes="['25350e1b1d0a64044af888b7f2ddaffd', '2c2fde409689aea61e5116108ec8e141', '67d534a0c8feb4098332ac3b4343efe1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(41984,1024) == "27a39c8bb354277dabe47b90087bc080"
}

