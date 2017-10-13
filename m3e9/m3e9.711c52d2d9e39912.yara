import "hash"

rule m3e9_711c52d2d9e39912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.711c52d2d9e39912"
     cluster="m3e9.711c52d2d9e39912"
     cluster_size="414 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['053fe013ad29e51611872876c4f2fc58', '14014094481873c00137162cb88bc03a', '14014094481873c00137162cb88bc03a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(9216,1024) == "fbad040c0983c3d7c7a05e828ed77efb"
}

