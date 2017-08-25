import "hash"

rule k3e9_3c1d3ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1d3ac9c4000b14"
     cluster="k3e9.3c1d3ac9c4000b14"
     cluster_size="1055 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['a1385f19594520c5445087ea55a1c853', '3ddc8c160725e85a494151ccfe691d99', '48a6fc5c005d412d2c45f4ad7ec54502']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6400,256) == "1371fd7f3206a21874fbe56ff62fb073"
}

