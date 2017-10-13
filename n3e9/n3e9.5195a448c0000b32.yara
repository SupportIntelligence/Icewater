import "hash"

rule n3e9_5195a448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.5195a448c0000b32"
     cluster="n3e9.5195a448c0000b32"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="expiro malicious dangerousobject"
     md5_hashes="['bd2f712cdc8575e973b0e0f4e596b3f5', 'c5a15b6b4a4e9dd44e8b4206e2d0776b', '44396411a6e3329a3595cbfe7d9858b4']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(17408,1280) == "684f852c35a1ca0ce42fe14f5ac4a831"
}

