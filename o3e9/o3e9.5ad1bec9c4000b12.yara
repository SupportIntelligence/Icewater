
rule o3e9_5ad1bec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.5ad1bec9c4000b12"
     cluster="o3e9.5ad1bec9c4000b12"
     cluster_size="24"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur ransom"
     md5_hashes="['0d071d18931bd01e7ef7d09a2e53a692','7543301f3bbba164a96d41c100b07b73','d5302670440a6ee12a1696a623766dc4']"

   strings:
      $hex_string = { 0c00f1860b00d692550063b0e7004088ce0013181b00171e24004a74b7006593cf0066a1e30069a3ea005988d9002d6ee4004878da006aa2ec006ca7ef004f80 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
