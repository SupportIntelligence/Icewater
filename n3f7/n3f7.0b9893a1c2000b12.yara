
rule n3f7_0b9893a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.0b9893a1c2000b12"
     cluster="n3f7.0b9893a1c2000b12"
     cluster_size="37"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack clicker clickjack"
     md5_hashes="['010f5ce33b443c9204283b64a6c158d0','0f237044742800e72dd60aacaa640148','7018f9b24066a5b8ae8830eb91333709']"

   strings:
      $hex_string = { 2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e746573 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
