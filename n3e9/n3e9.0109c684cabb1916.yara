import "hash"

rule n3e9_0109c684cabb1916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0109c684cabb1916"
     cluster="n3e9.0109c684cabb1916"
     cluster_size="1356 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="syncopate unwanted malicious"
     md5_hashes="['2d92a574f091280be84c76879cf51078', '0dd4e500fddfdb9bf4ffe999941d302b', '0da1b392f58e00e2e40d05aa2994bfa8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(247808,1024) == "2306275f1f24b134aa32f904209844da"
}

