import "hash"

rule m3e9_491c35b9c9020b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.491c35b9c9020b12"
     cluster="m3e9.491c35b9c9020b12"
     cluster_size="534 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="vobfus symmi vbkrypt"
     md5_hashes="['0b3637afb384006cbcf3d3d180226fec', '064f178632f5be12db2ac6c7536553a5', '803be571891a6523303de0ae1c679ed7']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(88064,1024) == "c35f60e9654d2c2e2a35e903b2ddc615"
}

