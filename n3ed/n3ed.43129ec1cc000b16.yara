import "hash"

rule n3ed_43129ec1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.43129ec1cc000b16"
     cluster="n3ed.43129ec1cc000b16"
     cluster_size="436 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['adca198a195883cbb02a14da04d50766', '8632c182e2261da2a79ea6945a72889b', 'ba7f9fac1f8de28d7ed0b1494fbd53a5']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(144896,1024) == "a90ca570b58c7536d80c1fbeac643413"
}

