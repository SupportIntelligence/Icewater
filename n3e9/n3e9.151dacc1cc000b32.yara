import "hash"

rule n3e9_151dacc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.151dacc1cc000b32"
     cluster="n3e9.151dacc1cc000b32"
     cluster_size="382 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack networm"
     md5_hashes="['afb5654b5b9ba1f8e773e03c81f95122', 'a40ce728b4b1e9d1a969c933755e64f6', 'aafbc5bc68e5c6c7aeb113a3206176df']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(83456,1024) == "4a4080ab9387ebb9aea646c2e4b067fe"
}

