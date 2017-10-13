import "hash"

rule m3e9_31b9e849c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31b9e849c0000b32"
     cluster="m3e9.31b9e849c0000b32"
     cluster_size="204 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="swrort elzob zusy"
     md5_hashes="['9de0215798c2d5e83ec33bf9fd744eea', '67a868feb751f22480906fb215d43efa', 'c91fa51f18fa38bf107b22d083c3ebc3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(50176,1024) == "ccb05ba3663aace23ac2314559358c25"
}

