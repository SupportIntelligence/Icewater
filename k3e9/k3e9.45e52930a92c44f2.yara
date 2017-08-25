import "hash"

rule k3e9_45e52930a92c44f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45e52930a92c44f2"
     cluster="k3e9.45e52930a92c44f2"
     cluster_size="241 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['2ce8620d9be53d32060fc0ca93e1d430', '9b42e74897645651c8b83856e1125701', 'de16df94e9aef57aef1d6ec83cd9a60d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(10752,256) == "cdb45c58a8e061e0a954c937bbb37d0c"
}

