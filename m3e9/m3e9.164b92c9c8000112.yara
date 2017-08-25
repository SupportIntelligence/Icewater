import "hash"

rule m3e9_164b92c9c8000112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.164b92c9c8000112"
     cluster="m3e9.164b92c9c8000112"
     cluster_size="5812 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="tinba crypt emotet"
     md5_hashes="['00d8178362876def87f332198c1ae227', '0381577d79a59a35ebea7d80d1c3cf99', '0813c65160001e0b44e094923668d195']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(11264,1024) == "2d8b2f9d1b2090a41972a5d66b4935a1"
}

