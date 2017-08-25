import "hash"

rule m3e9_5114eca0c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5114eca0c2000b32"
     cluster="m3e9.5114eca0c2000b32"
     cluster_size="3457 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="browsefox malicious riskware"
     md5_hashes="['135223092741a07b1b78ca249fe6f024', '07a244642ef558be6ff907c7a5196b2a', '02333a43338677b6a9ae8fee581e4783']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(87552,1127) == "3d144ccf65f6637c7f40ecd7c1725647"
}

