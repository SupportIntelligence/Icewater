import "hash"

rule m3e9_631c91e9c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631c91e9c2200b16"
     cluster="m3e9.631c91e9c2200b16"
     cluster_size="20 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack virut"
     md5_hashes="['c37ea58fa1a6d1ac6c506d543191e7de', 'de81df93fd7762a47a5fa23f54d7fa53', 'b02b47ab05bc55cda8c11c213ec65197']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(99262,1035) == "838a52846d283a2e8bf58bfaebeef5c9"
}

