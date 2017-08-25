import "hash"

rule j3e9_05a0b3e4cee30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.05a0b3e4cee30912"
     cluster="j3e9.05a0b3e4cee30912"
     cluster_size="138 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="rootkit dropped laqma"
     md5_hashes="['c4102663463d3088a3f8fdaeb9eb6dc7', 'c1d088066c33863098153039ef95fc42', 'd312316caf953fe63caa49c1cf20b086']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(6464,1088) == "47306964002b028b3366dd74864feb77"
}

