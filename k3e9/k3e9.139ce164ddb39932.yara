import "hash"

rule k3e9_139ce164ddb39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139ce164ddb39932"
     cluster="k3e9.139ce164ddb39932"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['6f6afeba8d1bcde99aeaf8786560b150', 'b4c17a413aa44bb7d90eb86735837d36', '6f6afeba8d1bcde99aeaf8786560b150']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12544,256) == "b563a84f7e0646b6239c507115d8d4a4"
}

