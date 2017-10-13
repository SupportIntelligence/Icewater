import "hash"

rule n3ec_11959999ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.11959999ca200b12"
     cluster="n3ec.11959999ca200b12"
     cluster_size="13302 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="parite pate bgvo"
     md5_hashes="['00db1f7be28d30ea69a4d96fec4780eb', '0d220a1927855dad7ef9fc7ef77b4ed3', '04ea70035675244ed5f65b4057704fde']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(410624,1024) == "297fcde3a8473f07462a33bd2acf4f6c"
}

