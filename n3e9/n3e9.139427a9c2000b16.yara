
rule n3e9_139427a9c2000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.139427a9c2000b16"
     cluster="n3e9.139427a9c2000b16"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod jadtre viking"
     md5_hashes="['6969c9c6ba4d8ea399cf80b08a92ba06','ae025fde8eed5f4f138f5dbd2550cf3d','fa640c79da1a062c32cac368cd8bd42c']"

   strings:
      $hex_string = { dba37267fff31a13b3b4ff30d75e55fa2a88223b451b2b773f1d77fe772fd6d5302a930c1fe8bb657e194e4d59db460e9317b7e8fd330f089babe4d368cd3e8c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
