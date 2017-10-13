import "hash"

rule n3e9_39c69569c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39c69569c8800b12"
     cluster="n3e9.39c69569c8800b12"
     cluster_size="181 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zusy trojandropper backdoor"
     md5_hashes="['da890906f005dc74cb731feaef35168e', 'a529fb7d3b6ff2ed351b6675e021956d', 'c05cca93c22e66d5244ca18751611351']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(138262,1046) == "66a1aad2b922cc836352280ff4cf1d3b"
}

