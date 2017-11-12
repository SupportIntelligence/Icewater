import "hash"

rule n3e9_414b1bd1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.414b1bd1c4000b12"
     cluster="n3e9.414b1bd1c4000b12"
     cluster_size="573 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob hpeg"
     md5_hashes="['137e63a82715afc60d6f509a8cff44e8', '095aa05736dd8a3bf0a3e69b2c47a38e', '9662af37c9a279a3c01d64fc0d799639']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(251392,1024) == "415b6503f0e0b2a014ea338b52fa4a12"
}

