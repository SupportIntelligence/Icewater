import "hash"

rule m3e9_43144888cb7b5132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.43144888cb7b5132"
     cluster="m3e9.43144888cb7b5132"
     cluster_size="5339 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="backdoor cripack vawtrak"
     md5_hashes="['234ea41a01edd53a01cf9857e5aad9bd', '0ee715f80c5720b6b41ddeea6bdb8f0e', '1315c37388cbcb42860ef39aa5188be7']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(200704,1024) == "5a2c5e94254309a31f721880a3fb930d"
}

