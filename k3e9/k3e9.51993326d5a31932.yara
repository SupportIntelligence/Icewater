import "hash"

rule k3e9_51993326d5a31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51993326d5a31932"
     cluster="k3e9.51993326d5a31932"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b135f11e9cff76fc43b9dbfc5cf1671f', 'a0ecbffa66405f0f02f7a492219ed028', 'df674bf56814b0ce89a567ec358fb00c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6144,1024) == "f79c58d33e2db2633697540b31321cf1"
}

