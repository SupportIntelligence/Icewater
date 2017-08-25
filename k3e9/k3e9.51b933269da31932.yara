import "hash"

rule k3e9_51b933269da31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b933269da31932"
     cluster="k3e9.51b933269da31932"
     cluster_size="843 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['47165a6ea0d53fd05728522005bd4550', 'a265dcc6db4153b64d48e6d203fe5758', '85c8c52334f9132c8a0cb7bf120413ba']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6144,1024) == "f79c58d33e2db2633697540b31321cf1"
}

