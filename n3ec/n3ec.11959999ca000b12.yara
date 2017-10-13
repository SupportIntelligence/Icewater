import "hash"

rule n3ec_11959999ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.11959999ca000b12"
     cluster="n3ec.11959999ca000b12"
     cluster_size="6101 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['0dff600aac5c383fbff981ff4ff4ef29', '16fb75e31033532a9e4ac5a3959a87e3', '13b76d3a48e94c8a8295ff736e9319bc']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(410624,1024) == "297fcde3a8473f07462a33bd2acf4f6c"
}

