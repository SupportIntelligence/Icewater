
rule n3ed_63161ae996c31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.63161ae996c31932"
     cluster="n3ed.63161ae996c31932"
     cluster_size="170"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox graftor razy"
     md5_hashes="['026a3eeb5a54876c5376a99a254c90e2','028b36d7432fa9ab9ef2d3096061a233','169e98ebbe6ccb6248001ecf42bbf0f4']"

   strings:
      $hex_string = { 01400000636d70736400000000000000000000000020111200201212000000000080000000fc000000100a000010140000000000020000000110000074657374 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
