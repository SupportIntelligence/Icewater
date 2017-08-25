import "hash"

rule k3e9_6b64d34f9a4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f9a4b4912"
     cluster="k3e9.6b64d34f9a4b4912"
     cluster_size="61 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['bff791cc1c9fc68a33f8446c496a5ca4', '97ff28b6e9bb3bb1a20948c950159982', 'ecd4ef98df28774a96949f0caa3766f7']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12396,1036) == "647cd7f4094d87659d4644490060e83e"
}

