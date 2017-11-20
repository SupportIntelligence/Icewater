
rule k2321_2a664a545a9348ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2a664a545a9348ba"
     cluster="k2321.2a664a545a9348ba"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['0f417a63a3fb5157d5eecb5927775c5d','5d1cc68f7ec893588b53030af79134fb','e53de6b1eaf47292218f6a278e8b1dff']"

   strings:
      $hex_string = { 756dc372ab8c61cbfd63e9bec68230ec8ed7f10cbfeac7569351337e4d5311b0028fed0a86b12d7d252bd3e10d6599b73e1d6a81cf8a45c8e766047f18d11958 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
