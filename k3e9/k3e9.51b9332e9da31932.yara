import "hash"

rule k3e9_51b9332e9da31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b9332e9da31932"
     cluster="k3e9.51b9332e9da31932"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['749fddfb4d439b59939f9f00ba0ed226', '9ec44a065929ad1a508c289a194d3433', '4242d1c9853e05bd707ed604d3e6f1e0']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6144,1024) == "f79c58d33e2db2633697540b31321cf1"
}

