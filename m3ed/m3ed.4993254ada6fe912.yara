import "hash"

rule m3ed_4993254ada6fe912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4993254ada6fe912"
     cluster="m3ed.4993254ada6fe912"
     cluster_size="1682 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="graftor palevo backdoor"
     md5_hashes="['523658632d76d55f81965d1a29bc09dc', 'a01ece3e3fe1a96304270db6b5dbfa16', '4e0dae7f05c6ef2b14e8978c0134347b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(201988,1045) == "7491b125c71abe23c4429519878a5332"
}

