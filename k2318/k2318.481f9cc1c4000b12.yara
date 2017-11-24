
rule k2318_481f9cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.481f9cc1c4000b12"
     cluster="k2318.481f9cc1c4000b12"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0d470ff51542aceaf56a3237134827b6','634d8de395cc104de06c5e4a2f2efa82','db4177798f86f6d9c422433b0b5550ed']"

   strings:
      $hex_string = { 747970653d27746578742f6a617661736372697074273e0a46422e696e6974287b0a617070496420203a202731353139353638313838333438323034272c0a73 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
