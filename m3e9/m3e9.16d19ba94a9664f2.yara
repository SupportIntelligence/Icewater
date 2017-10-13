import "hash"

rule m3e9_16d19ba94a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d19ba94a9664f2"
     cluster="m3e9.16d19ba94a9664f2"
     cluster_size="663 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="shipup razy zbot"
     md5_hashes="['a05e9ed6926482234e162149674c13cb', '6ede837b6d13096259961f7317d1c6e9', '45d8604181068751f14347a564dd0861']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(2048,1024) == "9967db6677f0ed6b8e78591467bc9e49"
}

