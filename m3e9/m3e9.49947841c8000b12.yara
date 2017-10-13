import "hash"

rule m3e9_49947841c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.49947841c8000b12"
     cluster="m3e9.49947841c8000b12"
     cluster_size="148 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a0ad26fd0698b95309165d04813747b7', '31f93aaad532b0e879c9095c6945fa44', 'b0259038441fcb6099c1e9eb1ec7855c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(45056,1024) == "1c6988d0d07f5236e1e21010cb5c1b28"
}

