import "hash"

rule m3e9_691f86e9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691f86e9c8800912"
     cluster="m3e9.691f86e9c8800912"
     cluster_size="250 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="nimnul vjadtre wapomi"
     md5_hashes="['b1941ffb4bc21eba096bf3c36732eadd', 'd000fa7ef8e7766a7036f5e96935e450', 'b433a4eee3ceba0bf7da5e9cecedb4e4']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1024) == "17bb2f77974ec7dfe7028de9f705c059"
}

