import "hash"

rule n3e9_2b1257a0dda30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b1257a0dda30912"
     cluster="n3e9.2b1257a0dda30912"
     cluster_size="6 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="startsurf ckua malicious"
     md5_hashes="['349ac1b7fc275f81c87ee815d1b17b7f', '145e46fe6b96bd70b320e13f731b8148', '0ea11f1a59cd6433de7afde5100826bb']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(637440,1024) == "e3314e9279ffe5dd230df0da68ddb854"
}

