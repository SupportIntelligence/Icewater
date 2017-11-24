
rule k2377_4b1d8cc1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.4b1d8cc1c4000b32"
     cluster="k2377.4b1d8cc1c4000b32"
     cluster_size="7"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0555d5e6b285276797e4f133c0f11cb0','26168bb452f3d71e63de359df34aad53','ab653a142cc837982940d05814710b4e']"

   strings:
      $hex_string = { 747970653d27746578742f6a617661736372697074273e0a46422e696e6974287b0a617070496420203a202731353139353638313838333438323034272c0a73 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
