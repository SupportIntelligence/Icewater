import "hash"

rule n3e9_199996c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.199996c9cc000b32"
     cluster="n3e9.199996c9cc000b32"
     cluster_size="153 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="softonic softonicdownloader unwanted"
     md5_hashes="['ba73d69f2dd4486da6952f350ad02f53', 'ff68c00d8cdb8af9c73843c62bf54415', '356223343bd16932b51df4034e03bdcc']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(357104,1058) == "437e574546bc1eed21f2b9a1f9fb0725"
}

