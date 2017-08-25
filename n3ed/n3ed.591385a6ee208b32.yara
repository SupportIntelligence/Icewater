import "hash"

rule n3ed_591385a6ee208b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.591385a6ee208b32"
     cluster="n3ed.591385a6ee208b32"
     cluster_size="359 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['284192ae890203676f060d4492b8f0b7', 'b1c3b158baec9c380f3aab18c0c6edee', 'af4dddb2e83e1d977a4dcae4ff0ac5f7']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(423936,1076) == "2464ede2d3405b3c500e9c2c3d78ec04"
}

