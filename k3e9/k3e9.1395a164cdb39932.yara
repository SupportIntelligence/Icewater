import "hash"

rule k3e9_1395a164cdb39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395a164cdb39932"
     cluster="k3e9.1395a164cdb39932"
     cluster_size="60 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a39db8b2e7f0378aace7c7c6a59a0c78', 'ac35cabaa5378ac3198c994fe65cf284', '40e4a68294e0d3aeedec8b7e3d6182c6']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "10942184959ee54e3c7f95e54fa08bca"
}

