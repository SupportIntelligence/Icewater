import "hash"

rule k3e9_32939612dec31b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.32939612dec31b16"
     cluster="k3e9.32939612dec31b16"
     cluster_size="101 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['1388f15f03d3d8a6f5308b5dfef519f8', 'ec2649cc01eb73a14b2204b2ea0b5470', '28dc8372181296870ed6d249d145bcf4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15360,256) == "cc66ac3c5629854ed877c268c081b668"
}

