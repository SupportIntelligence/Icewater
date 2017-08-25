import "hash"

rule o3e9_2996e448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2996e448c0000b12"
     cluster="o3e9.2996e448c0000b12"
     cluster_size="45 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="daws midie injector"
     md5_hashes="['6de76b945b9b462d5593583daf00cbc5', 'd9511c2e4c0ccdf2e2dc4acb23a197da', 'd624319e554a84f2de2c254c8ad6c739']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3584,1536) == "838666d924e8b6e9dfc84f930bd16733"
}

