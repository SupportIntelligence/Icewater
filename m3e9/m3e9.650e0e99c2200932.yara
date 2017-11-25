
rule m3e9_650e0e99c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.650e0e99c2200932"
     cluster="m3e9.650e0e99c2200932"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys pronny"
     md5_hashes="['1ae7abae46ed07f0a244a6a7dd8444ac','594038f9bba110559b74a29f3e89053f','d633cbb124746d568f7ff04d5d74501c']"

   strings:
      $hex_string = { 1711121a1f585765736c30599898989ab39e9e9ec0ceccaea9aadceff2f9fcfdfffffbf7b7000000fbffff0e1a1e1a1a18181a2965678687877878d9dcdcd2da }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
