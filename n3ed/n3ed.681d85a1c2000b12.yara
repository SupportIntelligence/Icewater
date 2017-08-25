import "hash"

rule n3ed_681d85a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.681d85a1c2000b12"
     cluster="n3ed.681d85a1c2000b12"
     cluster_size="367 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="malicious stantinko attribute"
     md5_hashes="['57112a0716dfecbdc4a212822291cb39', '73838fbf25bed0aaa01882a7e3b9771f', '03caa0cc21a33a1c30b83cbf50f2b4e6']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(230716,1031) == "bcc2aefe707ea2c6f27319da8977f5ca"
}

