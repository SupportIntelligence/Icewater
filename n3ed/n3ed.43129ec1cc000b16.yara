import "hash"

rule n3ed_43129ec1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.43129ec1cc000b16"
     cluster="n3ed.43129ec1cc000b16"
     cluster_size="432 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['4938c8cad841740d1984c8fe6dbd757d', 'a67fc425cad60af1d26b7f60282b882d', '718ab3c132faf43474664e9e0ded7d4c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(144896,1024) == "a90ca570b58c7536d80c1fbeac643413"
}

