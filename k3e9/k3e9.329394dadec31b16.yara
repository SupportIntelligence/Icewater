import "hash"

rule k3e9_329394dadec31b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.329394dadec31b16"
     cluster="k3e9.329394dadec31b16"
     cluster_size="1068 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ab22d02224b8c7c740d2f0747fae49a9', 'a17e4aa3c46ed5b97e638bbfdae7adb8', '7bb61ea9eb141d4cd4a301b1fe34107c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15360,256) == "cc66ac3c5629854ed877c268c081b668"
}

