import "hash"

rule o3e7_6136841089156b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.6136841089156b12"
     cluster="o3e7.6136841089156b12"
     cluster_size="16 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="speedingupmypc optimizerpro generickd"
     md5_hashes="['3ad7cc2a062d1ee405b1d340879ebf8c', 'ba7d4ed5f5e8ff5f35dfa0f9c8f2cc12', 'c57c344fffb3c446bea6f23231b3e1a6']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(15458,1031) == "7588218093864576f4f128a2f6634cb6"
}

