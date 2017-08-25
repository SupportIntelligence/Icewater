import "hash"

rule n3e9_2ab2a5e39c5b6b92
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2ab2a5e39c5b6b92"
     cluster="n3e9.2ab2a5e39c5b6b92"
     cluster_size="192 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="graftor delf genericr"
     md5_hashes="['971255da3ae5143a3b208d8d54da399b', 'f0ec93d1f18a8f7fbde8d8ee0c46a71c', '49de2dc692386d0534b9a0fec09444f0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(808156,1097) == "f916fcb4e7eb49133a5edb5e9ba8cf41"
}

