import "hash"

rule n3ed_0ca3390f1a12d132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ca3390f1a12d132"
     cluster="n3ed.0ca3390f1a12d132"
     cluster_size="115 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['a66b85c1d78420ba1fd8a46efbd80820', '4abe59f17a5c3f4d41b30f252baee61c', 'db3009bad67a4a58533a5c7a2b66b430']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(641536,1536) == "b83d54d068c17ef67e7b9236dbb3528c"
}

