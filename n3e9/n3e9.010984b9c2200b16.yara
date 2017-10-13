import "hash"

rule n3e9_010984b9c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.010984b9c2200b16"
     cluster="n3e9.010984b9c2200b16"
     cluster_size="154 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="syncopate unwanted malicious"
     md5_hashes="['db61b94e8b355458001eb43792194fc0', '3b2ce6ae53f1319eefe731eb0544190c', 'd15170caa0bed2f15e38ac7a7520d03c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(293888,1024) == "aa895101d05aeb1c4f348a7199cae7ab"
}

