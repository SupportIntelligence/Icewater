import "hash"

rule k3e9_51b93326d5a30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93326d5a30932"
     cluster="k3e9.51b93326d5a30932"
     cluster_size="76 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['9c758e895b42a721180a5688234ce641', 'df0c304b86d1360860f2ab85de629731', 'c5712c384a7c3829b0a26d32f821fd26']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,256) == "9e015b774cd4f7548c9bde3a60e79ccb"
}

