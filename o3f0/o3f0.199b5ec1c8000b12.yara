import "hash"

rule o3f0_199b5ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.199b5ec1c8000b12"
     cluster="o3f0.199b5ec1c8000b12"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="malicious fner icloader"
     md5_hashes="['6075a07101cf1b4ea1011f2fe635cbbf', 'c31fec753e4e23c792a33ee0b5c0d16f', '6075a07101cf1b4ea1011f2fe635cbbf']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1249280,1024) == "422c688d1b93d8df3935d4e78be67fb2"
}

