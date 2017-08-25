import "hash"

rule n3ed_5913c5a6fe631b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.5913c5a6fe631b32"
     cluster="n3ed.5913c5a6fe631b32"
     cluster_size="171 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['9a1bd31fd45ccc00a54e65d70a336c17', '7329ab21d04c6208e181b6e8a80d1a89', 'b5cfe2f9fd1b46be1e3967155abde8fb']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(440662,1109) == "db48825dadc71a665893ba382ddae571"
}

