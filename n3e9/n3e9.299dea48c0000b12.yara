import "hash"

rule n3e9_299dea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.299dea48c0000b12"
     cluster="n3e9.299dea48c0000b12"
     cluster_size="9271 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="strictor constructor houndhack"
     md5_hashes="['12cc268b134c99457155c2e17f1cd7fb', '0c08fada3f3e7ade9bbe0fc933925326', '13cc9b88fdb9acdbd12a8af77b914b1b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(48174,1025) == "23737fccc855d85cc60a11b890e6791d"
}

