import "hash"

rule n3e9_499a96c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.499a96c9cc000b12"
     cluster="n3e9.499a96c9cc000b12"
     cluster_size="186 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="softonic softonicdownloader unwanted"
     md5_hashes="['49f1fce7269d1099f64de13c4fcd945b', '2aeb99fb7a23fd5ef3a68a7a9ef0ce6e', '5d6155ef605c16bce5df1e6014a8570f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(357104,1058) == "437e574546bc1eed21f2b9a1f9fb0725"
}

