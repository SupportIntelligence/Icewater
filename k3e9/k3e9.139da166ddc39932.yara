import "hash"

rule k3e9_139da166ddc39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da166ddc39932"
     cluster="k3e9.139da166ddc39932"
     cluster_size="188 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['df49a653c0791b45a319ff0706c262f7', 'cafb4c5abb2ae4c2716105679e8cc21b', 'e93091ad11951166e553d5aaf815d8e6']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1024) == "19f46802217b7e74f63dc75432304b31"
}

