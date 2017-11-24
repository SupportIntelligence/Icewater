
rule k2377_081b9ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.081b9ec1c4000b12"
     cluster="k2377.081b9ec1c4000b12"
     cluster_size="9"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['57385b7ad339f2e6f617f7d6d2e6674a','5c93b0d8962e0457aa82ee2822452ad5','d8dfff26b4784f950caae87514ede8cf']"

   strings:
      $hex_string = { 747970653d27746578742f6a617661736372697074273e0a46422e696e6974287b0a617070496420203a202731353139353638313838333438323034272c0a73 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
