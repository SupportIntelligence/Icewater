import "hash"

rule k3e9_63146ff11d827b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ff11d827b16"
     cluster="k3e9.63146ff11d827b16"
     cluster_size="425 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c52f2a7e9180e0572f048c57eacc6cd6', 'c9fe8fb1629005b97910eae5846b84ce', 'a5538ecfa8d7d6bc352d4cfb691ae6ef']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

