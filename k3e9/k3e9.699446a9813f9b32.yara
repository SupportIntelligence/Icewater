import "hash"

rule k3e9_699446a9813f9b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.699446a9813f9b32"
     cluster="k3e9.699446a9813f9b32"
     cluster_size="6517 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="jqap small zbot"
     md5_hashes="['08a1f0b87b720c5ecfb7e4b0851acda4', '0c79d0278903d79f8570b0ca8e00d5da', '0a1378b66208cebfe1a33acfa88150ab']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,1024) == "46ed381652e45b6d895092742666b2db"
}

