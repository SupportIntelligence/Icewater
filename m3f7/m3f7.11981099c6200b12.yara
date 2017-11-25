
rule m3f7_11981099c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.11981099c6200b12"
     cluster="m3f7.11981099c6200b12"
     cluster_size="25"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html inor"
     md5_hashes="['1396e4c16053a9ccadcee2dfc1f69c8b','14ba059aebd96430968e20f8ad53dcdf','993b1b6d09e1038f3a4e8333f45ac8d7']"

   strings:
      $hex_string = { 42433433363844323238374645334646364130344136433635363933304233444342324539373438453031343733413646354244393538303432313241373545 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
