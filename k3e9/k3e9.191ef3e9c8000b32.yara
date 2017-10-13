import "hash"

rule k3e9_191ef3e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.191ef3e9c8000b32"
     cluster="k3e9.191ef3e9c8000b32"
     cluster_size="128 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['bd1829161b51bb3961dd3cd05d05dcff', '884c32e33855a32e96b2c2d0fb7b4eeb', 'b98d068a177cba1e49ac4be70f75bddc']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

