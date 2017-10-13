import "hash"

rule m3e9_31b9e849c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31b9e849c0000912"
     cluster="m3e9.31b9e849c0000912"
     cluster_size="552 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="swrort elzob zusy"
     md5_hashes="['2f4126270fdf223fa5839b26c4567fe8', '11e6e8a5327d99beb2b20ce882fced68', '08cb22d17053ab16141738f09241cd87']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62464,1024) == "1db9d97aa3077042ff06074d16a50ac7"
}

