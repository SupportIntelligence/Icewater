import "hash"

rule k3e9_51b13336dba31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13336dba31b32"
     cluster="k3e9.51b13336dba31b32"
     cluster_size="7 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b0e332d299d90c8775c78179e136c92d', 'a10f60e016b0b95559317eaa8f17adda', 'af30dc9c2fee03672ffed108a0fc1e0b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,1024) == "8013aec142278ae2253a325ded189d2a"
}

