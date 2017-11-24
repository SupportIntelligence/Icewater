
rule m2377_495c12c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.495c12c9c4000b12"
     cluster="m2377.495c12c9c4000b12"
     cluster_size="11"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="loic flooder html"
     md5_hashes="['4d5bc4d9a52537ba0bf7b9970763ddd0','54b74330d8cf132a221a685dd192bf19','fb7aaef3882b23151fe51ca08a3ff996']"

   strings:
      $hex_string = { 3933575731615042794769634535366c7350756665744a6b2b7870677878634a704856694e49412f576f7a37524c4b66686c38317246645473675658544d6a5a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
