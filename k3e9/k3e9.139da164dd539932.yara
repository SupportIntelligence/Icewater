import "hash"

rule k3e9_139da164dd539932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da164dd539932"
     cluster="k3e9.139da164dd539932"
     cluster_size="11 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['8fb334383897d62c67ca3d5413cb1ddc', '712fed656a3e98f3be1b1939ef4ca2b4', 'a53023ccb07961c9bbff56fdaaa1eb8c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1024) == "19f46802217b7e74f63dc75432304b31"
}

