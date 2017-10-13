import "hash"

rule o3ed_131a9db9d68b0916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.131a9db9d68b0916"
     cluster="o3ed.131a9db9d68b0916"
     cluster_size="660 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['a0ccf5b81930d017728983456f8c043a', 'a7e5775512c77bef02c8d20d7c6f212f', '1dcc8916dca91b418f6eeb5648b92779']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2183168,1024) == "0e6e52e26906a323049b5f94126f2295"
}

