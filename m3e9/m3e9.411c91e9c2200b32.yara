import "hash"

rule m3e9_411c91e9c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411c91e9c2200b32"
     cluster="m3e9.411c91e9c2200b32"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple virut rahack"
     md5_hashes="['4f74085de6082849fa5641f4664dd4e3', '0bc1abb9294b58c6846b3f4f2c82b28e', 'b12a6126befc492af99f46ba8e5787b8']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(99262,1035) == "838a52846d283a2e8bf58bfaebeef5c9"
}

