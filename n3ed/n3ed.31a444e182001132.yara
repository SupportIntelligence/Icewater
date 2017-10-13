import "hash"

rule n3ed_31a444e182001132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a444e182001132"
     cluster="n3ed.31a444e182001132"
     cluster_size="347 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['c742b2f8f438021fc068995f70ce900f', '84cc1c7b37cc5baf013f48259f7eaddb', 'ad761dbdb43b6518b147fc081a2f5bfd']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(286720,1024) == "21cd1f5dd6f252371e6aa6e53f74b815"
}

