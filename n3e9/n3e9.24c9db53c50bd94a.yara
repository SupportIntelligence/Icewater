
rule n3e9_24c9db53c50bd94a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.24c9db53c50bd94a"
     cluster="n3e9.24c9db53c50bd94a"
     cluster_size="67"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="softonic softonicdownloader malicious"
     md5_hashes="['03c6573fd78c986d4063fa775be7fdbf','05f5a00253ee5e22690f701baf885897','44ea15455dd5f119453ed01f78837aaa']"

   strings:
      $hex_string = { 094cbf3d05dcebf5c6751c00b4f7c64a92fc886d07efbd6ab59a5aadd6c71e238011daedb69e3e7d2aef4726288d6835ca3cb0996efd513fb9b474b3fbecd91f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
