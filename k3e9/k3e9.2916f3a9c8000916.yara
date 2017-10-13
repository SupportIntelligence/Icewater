import "hash"

rule k3e9_2916f3a9c8000916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2916f3a9c8000916"
     cluster="k3e9.2916f3a9c8000916"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="backdoor razy injector"
     md5_hashes="['d1dd8bfd3c534c301727079655f3ee87', 'ae75c81d187342f60be0f264fe4df003', 'ac24e5c2778a44f1454b95d463ae907c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

