import "hash"

rule m3e9_6916d7a9c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6916d7a9c2000912"
     cluster="m3e9.6916d7a9c2000912"
     cluster_size="80 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['df168bdc0306fe79fbebd946199720ad', 'a3e3d59f3e80aeaf34690cd8589a6c10', 'c533c53c8cf71e2880b2662aa3e80c2a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(74752,1024) == "9dd737489d4f545899488dd359173093"
}

