import "hash"

rule n3e9_291257a0dda30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.291257a0dda30932"
     cluster="n3e9.291257a0dda30932"
     cluster_size="4 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="ckua startsurf malicious"
     md5_hashes="['697136ef6328d32061e993a68195ff1d', '9b194d8a9bb2a25bd3bc700219933b49', '697136ef6328d32061e993a68195ff1d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(637440,1024) == "e3314e9279ffe5dd230df0da68ddb854"
}

