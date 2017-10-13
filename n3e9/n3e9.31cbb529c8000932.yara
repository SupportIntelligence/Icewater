import "hash"

rule n3e9_31cbb529c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31cbb529c8000932"
     cluster="n3e9.31cbb529c8000932"
     cluster_size="7233 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['082dd7406480ccb1755d922256c4a3d5', '05e1b9fb807eb4079655cbdd569eca5f', '02ea41242fae516649cd31e70084a86b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(142763,1109) == "3e153f591f3d402724f89d1593be1ca7"
}

