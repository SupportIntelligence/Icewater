import "hash"

rule n3e9_049d9ac1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.049d9ac1c4000932"
     cluster="n3e9.049d9ac1c4000932"
     cluster_size="8208 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['08efec9097d0bdef8a38e9f78e393fa8', '080e6e60bad4a853285733735aea6c2f', '06f8b8db949946d010afb5edb6cc53d1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(278528,1024) == "49fedfe9d66be3a6026b41fc3b0e9b08"
}

