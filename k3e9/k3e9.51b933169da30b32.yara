import "hash"

rule k3e9_51b933169da30b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b933169da30b32"
     cluster="k3e9.51b933169da30b32"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a8e9a0643dd809b8b9c1a8ec336be04f', 'b05e7b5ee88a90d15c1a8d5239d2e3bd', 'b35766a1f8e6bac85a0546c52e6e3823']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,1024) == "8013aec142278ae2253a325ded189d2a"
}

