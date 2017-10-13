import "hash"

rule n3e9_131ae5a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.131ae5a1c2000b32"
     cluster="n3e9.131ae5a1c2000b32"
     cluster_size="402 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple virut rahack"
     md5_hashes="['cd70094b5471cf68f8f408b6550d4b2e', '65ca56ed299aa8261a40419e124e19f0', 'c60ccfac5ef92a26ae280ea5b289c7a7']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(61952,1024) == "6a039dc6f36c112b920bef9b8a73cb0e"
}

