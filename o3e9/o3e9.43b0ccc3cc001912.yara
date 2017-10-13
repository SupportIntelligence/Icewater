import "hash"

rule o3e9_43b0ccc3cc001912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0ccc3cc001912"
     cluster="o3e9.43b0ccc3cc001912"
     cluster_size="4528 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="parite madang small"
     md5_hashes="['16413b8239decff2d576896614e45b72', '1252f1a24d43de843859020884c9786c', '05a54aa3089dee29dd46a698eb0b2b8a']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(823296,1024) == "87eb1721305da946a1b87ff9207f629a"
}

