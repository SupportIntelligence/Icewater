import "hash"

rule k3e9_1395a164dc939932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395a164dc939932"
     cluster="k3e9.1395a164dc939932"
     cluster_size="61 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c67a93bc3c738feef5ae1c4b86d5da69', 'f7ca546dcfb38b71240e818f26b06294', 'a51961591919f8916cf6a12da109fd38']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,1024) == "9d50f87de03c29a87bc27db9932cf548"
}

