import "hash"

rule k3e9_139da166ddab9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da166ddab9932"
     cluster="k3e9.139da166ddab9932"
     cluster_size="132 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['cc7e37f69215f1d1007c1dcc9a9a2eed', 'c16fa59dd08aebbc19507e8cdbcb90b8', '8b0183521eeb50cc3591ebd54cf3e1dc']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12544,256) == "b563a84f7e0646b6239c507115d8d4a4"
}

