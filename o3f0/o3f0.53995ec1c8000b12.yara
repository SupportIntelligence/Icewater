import "hash"

rule o3f0_53995ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.53995ec1c8000b12"
     cluster="o3f0.53995ec1c8000b12"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="malicious fner icloader"
     md5_hashes="['7cebe04402f2a856fe4ed55f5d21fd33', 'b13797045b119033eeb2868fb86c9472', 'cb191a2077b1ea7aa3fbe4c7182c457e']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1272832,1024) == "1d2fdb98df1a68ea5c90cfccb6318eb0"
}

