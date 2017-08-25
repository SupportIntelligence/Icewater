import "hash"

rule k3e9_17e30b931ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e30b931ee31132"
     cluster="k3e9.17e30b931ee31132"
     cluster_size="35 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c6cb0d77e63810ba96440acb499ce9b6', 'ba4b6832b9c83aa7c9c1c29b074433de', 'b60247dd0e2c64f32e69ec582233ab0c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "2f71af6522927f93cb15efa00c89d5db"
}

