import "hash"

rule k3e9_17c309561ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17c309561ee311b2"
     cluster="k3e9.17c309561ee311b2"
     cluster_size="3 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['030b13cd5bf7d06c9e34c31fc57484d0', 'ad0d21858151394085926f2f40efa8f1', 'ad0d21858151394085926f2f40efa8f1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18432,1024) == "10e9282cad49722b603d799d81e34b3d"
}

