import "hash"

rule n3e9_299657a0dda30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.299657a0dda30912"
     cluster="n3e9.299657a0dda30912"
     cluster_size="5 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="ckua malicious startsurf"
     md5_hashes="['4f235dcf49f8359feff22a64c0f36982', 'b382bcba87786139db6e641d4348554b', 'ece8e86e4cc907f98cd410ae84144274']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(637440,1024) == "e3314e9279ffe5dd230df0da68ddb854"
}

