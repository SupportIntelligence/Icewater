import "hash"

rule n3e9_16bb25a1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.16bb25a1c2000912"
     cluster="n3e9.16bb25a1c2000912"
     cluster_size="194 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a646b445540abd0009a09edfcb23d0b8', 'f734767fa1410c2e7b65ceae6eb42cc5', 'f8ba461f072b41ddd3177f12ef38355e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(100864,1024) == "67f2b9682a09d09611240adeecd10747"
}

