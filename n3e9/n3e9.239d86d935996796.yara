import "hash"

rule n3e9_239d86d935996796
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.239d86d935996796"
     cluster="n3e9.239d86d935996796"
     cluster_size="292 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="driverupdate malicious engine"
     md5_hashes="['148204577b567eaf28537c6eb1c069a6', 'd9d73422950a986bffbbc301b75705ef', 'af2ecffee9cebcc85b663d284dd0511f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(438272,1024) == "f0986c62ce4c397d01d89277127e9397"
}

