import "hash"

rule n3ec_11959999ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.11959999ca200b12"
     cluster="n3ec.11959999ca200b12"
     cluster_size="21883 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="parite pate bgvo"
     md5_hashes="['059fc1e9d9fbbb896c281e6ef9b0fa1f', '09ebcdb3cfdf2877ebfc8b49f3ad7a76', '0139ffedf63b11e5af3f65b4be6acedb']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(410624,1024) == "297fcde3a8473f07462a33bd2acf4f6c"
}

