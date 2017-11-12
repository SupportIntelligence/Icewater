import "hash"

rule n3ec_11959999ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.11959999ca000b12"
     cluster="n3ec.11959999ca000b12"
     cluster_size="10001 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['17d1b8b8829536fd7ec5df15981c6013', '0ed3df35739402ffb628e166e0c5e4af', '0f8b93a624641d96001095b92e81e013']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(410624,1024) == "297fcde3a8473f07462a33bd2acf4f6c"
}

