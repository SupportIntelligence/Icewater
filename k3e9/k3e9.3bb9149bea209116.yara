
rule k3e9_3bb9149bea209116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3bb9149bea209116"
     cluster="k3e9.3bb9149bea209116"
     cluster_size="242"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre kryptik malicious"
     md5_hashes="['0105991d82890f48c487b6264b9d1132','07219830f152ec1f2f095aa771253670','1deb05b0ea2da9a2e7d8d9ef36929451']"

   strings:
      $hex_string = { 736d76333a73656375726974793e0a202020203c6d735f61736d76333a72657175657374656450726976696c656765733e0a2020202020203c6d735f61736d76 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
