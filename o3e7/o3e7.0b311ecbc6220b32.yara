
rule o3e7_0b311ecbc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.0b311ecbc6220b32"
     cluster="o3e7.0b311ecbc6220b32"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr malicious banker"
     md5_hashes="['3ed8ccd44cf1d1f9beabdb4b6668ad7d','499e571b23fe14964af6794b5769e446','77cc35170d5c881407cf6c7803ddab33']"

   strings:
      $hex_string = { e5116745ac20602c72be65966bbcfd6a63d2b8c1a448cbaab6531f9c1ef3abeb58ae7dadbae0a3a75bcf8c88b53e19f25a2623d825bfec2a108a5200a1229f57 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
