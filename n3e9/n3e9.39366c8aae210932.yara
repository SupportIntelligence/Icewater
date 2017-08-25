import "hash"

rule n3e9_39366c8aae210932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39366c8aae210932"
     cluster="n3e9.39366c8aae210932"
     cluster_size="17 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e0f6a29bf0ad2c70184ae73c7477151f', '4124eb76f76b711712b45f1c4f2e1948', 'b96a1096cc579a179767f8ca80f61dd9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(61440,1024) == "821913283c3a548032a8ee12e97d41d2"
}

