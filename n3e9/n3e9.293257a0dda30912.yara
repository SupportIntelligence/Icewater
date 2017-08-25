import "hash"

rule n3e9_293257a0dda30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.293257a0dda30912"
     cluster="n3e9.293257a0dda30912"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="ckua startsurf malicious"
     md5_hashes="['b779b5add6c7d95eb078c3350b139e83', 'a6862f5ef6ee083db4f3dd51282b1d3d', 'b779b5add6c7d95eb078c3350b139e83']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(637440,1024) == "e3314e9279ffe5dd230df0da68ddb854"
}

