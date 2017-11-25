
rule m3e9_53302c26ddcb7916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.53302c26ddcb7916"
     cluster="m3e9.53302c26ddcb7916"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi wecod cardspy"
     md5_hashes="['64a4445c8537dc3ebe47353c953a1092','bf9712b7bdfb6449ca28ab81ed8b2626','e7a2c5f4a142555eac310a81244858dc']"

   strings:
      $hex_string = { 667a821bcce66119cd26e1ec4e1ef8c5fef07e0a01f2cb6cb0c85e098663ffaebadbc97ab6bce573bf2f9c70393035c418f6535f1cf31afbe34704af9dc78b33 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
