
rule n3f4_213210aad9af4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.213210aad9af4912"
     cluster="n3f4.213210aad9af4912"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kryptik malicious tuto"
     md5_hashes="['03e62eef03237a673e07e9bfa8e6a239','1f64f46b66352caec0e7612fad1f49fb','e5acc930ae775d07d8eeaefe44587a59']"

   strings:
      $hex_string = { 6533754a6b7276302f3178514c4862493267683077424d6448523670543571635a6d384b65426c32517a636e525870794e314546365655676f392b66426d3444 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
