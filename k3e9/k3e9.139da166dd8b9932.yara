import "hash"

rule k3e9_139da166dd8b9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da166dd8b9932"
     cluster="k3e9.139da166dd8b9932"
     cluster_size="277 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e22e775c11f8f78e6cff8a73c999fd1b', 'ddedad524fca5eb04a82873ce236de69', '489cac23cc1f3f6c215cf3923c893ddf']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,1024) == "9d50f87de03c29a87bc27db9932cf548"
}

