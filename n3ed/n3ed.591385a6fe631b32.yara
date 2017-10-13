import "hash"

rule n3ed_591385a6fe631b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.591385a6fe631b32"
     cluster="n3ed.591385a6fe631b32"
     cluster_size="273 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['fc8321f26e41ddf39fb78ab858cf73f0', 'a3e04b348fb7845846259ecb0db12077', '7b8c6bb795b91d20bc3afa82cd902e26']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(440662,1109) == "db48825dadc71a665893ba382ddae571"
}

