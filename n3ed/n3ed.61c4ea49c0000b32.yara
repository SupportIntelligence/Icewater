import "hash"

rule n3ed_61c4ea49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.61c4ea49c0000b32"
     cluster="n3ed.61c4ea49c0000b32"
     cluster_size="38 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['ac0f2ecc720617633398aa3ef0ae3a81', '45a0059ec7cfbf8a1503f8b0fc27ef80', 'ba88810260d7e070d88cd35e422a515f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(156672,1536) == "0f4c07f5fc878e2aa1805fefc0c25f7a"
}

