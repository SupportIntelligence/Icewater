
rule k2377_4a1e9cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.4a1e9cc1c4000b12"
     cluster="k2377.4a1e9cc1c4000b12"
     cluster_size="13"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0973a2c995642adebb9d2ba9021d43cc','2cf03338984f25525f23699f95f8b431','e7fd1e045e92bcb66d7bfdb95c2f9ff4']"

   strings:
      $hex_string = { 7970653d27746578742f6a617661736372697074273e0a46422e696e6974287b0a617070496420203a202731353139353638313838333438323034272c0a7374 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
