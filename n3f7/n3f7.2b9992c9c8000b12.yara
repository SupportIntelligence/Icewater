
rule n3f7_2b9992c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.2b9992c9c8000b12"
     cluster="n3f7.2b9992c9c8000b12"
     cluster_size="21"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack clicker clickjack"
     md5_hashes="['0c6086dd6021a6405eaca3877b299aae','0e102e65f4f8d807275e895fe0e7c1f4','bf5d65967951a918e6793f5b7366e817']"

   strings:
      $hex_string = { 2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e746573 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
