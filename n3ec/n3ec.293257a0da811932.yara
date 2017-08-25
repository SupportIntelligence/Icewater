import "hash"

rule n3ec_293257a0da811932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.293257a0da811932"
     cluster="n3ec.293257a0da811932"
     cluster_size="3 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="strictor malicious startsurf"
     md5_hashes="['9e50b67d0365f50bc1a708832c1b4020', '9e50b67d0365f50bc1a708832c1b4020', '38609af47cb4de45c021497d7faf6266']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(614400,1024) == "1f61e40016cadcc04a35b35dd3b3eb71"
}

