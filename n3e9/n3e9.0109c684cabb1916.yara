import "hash"

rule n3e9_0109c684cabb1916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0109c684cabb1916"
     cluster="n3e9.0109c684cabb1916"
     cluster_size="1302 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="syncopate unwanted malicious"
     md5_hashes="['2afd006d2a6bba8bf6a9b815e9c3cf1e', '3c543f212a02e579c7ae10ee5c6c9356', '1d83da189904a1c8413f04eff85be4b3']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(247808,1024) == "2306275f1f24b134aa32f904209844da"
}

