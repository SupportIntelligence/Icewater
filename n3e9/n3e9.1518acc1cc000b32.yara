import "hash"

rule n3e9_1518acc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1518acc1cc000b32"
     cluster="n3e9.1518acc1cc000b32"
     cluster_size="2281 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="allaple rahack networm"
     md5_hashes="['0b53b6cf656a139298b45dfb8c80e737', '37cd89d0d15abd43b6a142021e36106f', '28c48e8f1945fc8c6ad4e36710e89a78']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(83456,1024) == "4a4080ab9387ebb9aea646c2e4b067fe"
}

