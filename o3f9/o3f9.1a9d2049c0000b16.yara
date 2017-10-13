import "hash"

rule o3f9_1a9d2049c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f9.1a9d2049c0000b16"
     cluster="o3f9.1a9d2049c0000b16"
     cluster_size="53585 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="kovter pemalform riskware"
     md5_hashes="['013b181eed367ccb9fdae9c109da686e', '0119a93ab89fd021feed0e3351e14077', '0083b61da0344d51c548e4422690b667']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(510464,1024) == "a3b2c647dcc2af1085a35045ea36ae83"
}

