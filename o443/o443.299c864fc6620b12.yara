import "hash"

rule o443_299c864fc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o443.299c864fc6620b12"
     cluster="o443.299c864fc6620b12"
     cluster_size="400 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="bitcoinminer ierh multi"
     md5_hashes="['9a6850f8cdf48b978253b3704b3c94f8', '7a5b7574e87ea0a9d3fe29389a1d7b00', '7a333a913dd8014d03e660418401fb36']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(765440,1024) == "692d6ae219f1cdc2df5670670f8bf8aa"
}

